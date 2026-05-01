#include "fnp_master.h"
#include "fnp_frontend.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "fnp_worker.h"
#include "fnp_api.h"
#include "fapi.h"
#include "hash.h"
#include "gtpu.h"

#include <errno.h>
#include <rte_ethdev.h>

#include <unistd.h>

typedef struct fnp_master_retire_item
{
    fsocket_t *socket;
    fsocket_release_func_t release;
} fnp_master_retire_item_t;

fmaster_context_t master;

static void drain_retired_sockets(void)
{
    if (master.retire_chan == NULL)
    {
        return;
    }

    eventfd_t value = 0;
    while (eventfd_read(master.retire_chan->event_fd, &value) == 0)
    {
    }

    u32 pending = fnp_ring_count(master.retire_chan->ring);
    fnp_master_retire_item_t *item = NULL;
    for (u32 i = 0; i < pending; ++i)
    {
        if (fnp_ring_dequeue(master.retire_chan->ring, (void **)&item) == 0)
        {
            break;
        }

        if (item != NULL)
        {
            if (item->socket != NULL)
            {
                (void)fnp_master_remove_fsocket(item->socket);
            }
            if (item->release != NULL)
            {
                item->release(item->socket);
            }
            fnp_free(item);
        }
    }
}

static void close_frontend_sockets(fnp_frontend_t *frontend)
{
    if (frontend == NULL)
    {
        return;
    }

    rte_spinlock_lock(&frontend->lock);
    frontend->socket_num = 0;
    for (u32 i = 0; i < frontend->socket_capacity; ++i)
    {
        fsocket_t *socket = frontend->sockets[i];
        if (socket == NULL)
        {
            continue;
        }

        frontend->sockets[i] = NULL;
        fsocket_detach_frontend(socket);
        close_fsocket(socket);
    }
    rte_spinlock_unlock(&frontend->lock);
}

// main lcore调用，检查fnp-frontend是否正常
// daemon的控制线程添加frontendTbl
static void check_frontend_alive()
{
    fnp_list_node_t *node = fnp_list_first(&master.frontend_list);
    while (node != NULL)
    {
        fnp_frontend_t *frontend = node->value;
        fnp_list_node_t *next_node = fnp_list_get_next(node);
        if (frontend->alive)
        {
            frontend->alive = 0;
            frontend->fail_cnt = 0;
        }
        else
        {
            frontend->fail_cnt++;
            if (frontend->fail_cnt > 3)
            {
                FNP_INFO("frontend %d fail to keepalive, start to delete!!!\n", frontend->pid);
                // 从master删除该前端
                fnp_list_delete(&master.frontend_list, node);

                close_frontend_sockets(frontend);

                // 删除该前端
                frontend_free(frontend);
            }
        }
        node = next_node;
    }
}

static void check_daemon_info(FILE *fp)
{
    static u64 prev_tsc = 0;
    show_mempool_info();

    const int port_id = 0;

    u64 tsc = fnp_get_tsc();
    if (prev_tsc == 0)
    {
        prev_tsc = tsc;
        rte_eth_stats_reset(port_id);
        return;
    }

    struct rte_eth_stats stats;
    rte_eth_stats_get(port_id, &stats);

    fnp_rate_measure_t recv_meas = {0};
    recv_meas.file = fp;
    recv_meas.first_tsc = prev_tsc;
    recv_meas.last_tsc = tsc;
    recv_meas.packet_count = stats.ipackets;
    recv_meas.byte_count = stats.ibytes;
    fnp_compute_rate(&recv_meas);

    fnp_rate_measure_t send_meas = {0};
    send_meas.file = fp;
    send_meas.first_tsc = prev_tsc;
    send_meas.last_tsc = tsc;
    send_meas.packet_count = stats.opackets;
    send_meas.byte_count = stats.obytes;
    fnp_compute_rate(&send_meas);

    prev_tsc = tsc;
    rte_eth_stats_reset(port_id);
}

static void write_worker_rx_info(FILE *fp)
{
    fprintf(fp, "worker_rx");
    for (int id = 0; id < get_fnp_worker_count(); ++id)
    {
        fnp_worker_t *worker = get_fnp_worker(id);
        if (worker == NULL)
        {
            continue;
        }

        fprintf(fp,
                " worker%d_queue%d_ingress_sockets=%u worker%d_egress_sockets=%d",
                worker->id,
                worker->queue_id,
                worker->ingress_socket_count,
                worker->id,
                worker->egress_socket_count);
    }
    fprintf(fp, "\n");
    fflush(fp);
}

static void log_device_eth_stats_from_master(void)
{
}

int fnp_master_add_fsocket(fsocket_t *socket)
{
    int fd = socket->tx_efd_in_backend;
    struct epoll_event ev = {0};   // 注意，必须初始化为0，否则read value会有异常
    ev.events = EPOLLIN | EPOLLET; // 边沿触发，正常是指0到非0值才会触发，与epoll配合后，值变化就会触发
    ev.data.ptr = (void *)socket;
    // 注意ev.data是一个union，ptr,fd,u32和u64只能设置一个值。

    int ret = epoll_ctl(master.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    if (ret != 0)
    {
        return FNP_ERR_ADD_EVENTFD;
    }

    return FNP_OK;
}

int fnp_master_remove_fsocket(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (!fsocket_master_take_registered(socket))
    {
        return FNP_OK;
    }

    if (socket->tx_efd_in_backend >= 0 &&
        epoll_ctl(master.epoll_fd, EPOLL_CTL_DEL, socket->tx_efd_in_backend, NULL) != 0 &&
        errno != ENOENT && errno != EBADF)
    {
        return FNP_ERR_DEL_EVENTFD;
    }

    return FNP_OK;
}

int fnp_master_retire_fsocket(fsocket_t *socket, fsocket_release_func_t release)
{
    if (socket == NULL || release == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (master.retire_chan == NULL)
    {
        return FNP_ERR_NOT_FOUND;
    }

    fnp_master_retire_item_t *item = fnp_malloc(sizeof(*item));
    if (item == NULL)
    {
        return FNP_ERR_MALLOC;
    }

    item->socket = socket;
    item->release = release;
    if (!fchannel_enqueue(master.retire_chan, item))
    {
        fnp_free(item);
        return FNP_ERR_RING_FULL;
    }

    return FNP_OK;
}

static void handle_fsocket_event(fsocket_t *socket, u64 event)
{
    if (socket == NULL || socket->tx == NULL || fsocket_is_closing(socket))
    {
        return;
    }

    // 有数据要发送
    if (likely(event < fsocket_event_close))
    {
        fnp_worker_add_fsocket(socket);
    }
    else
    {
        // connect or close event
    }
}

void fnp_master_loop()
{
#define MAX_EVENTS 32
    struct epoll_event evs[MAX_EVENTS];

    printf("start task to manage frontend\n");
    FILE *fp = fopen("./fnp_master_stat.txt", "w");
    if (fp == NULL)
    {
        perror("Failed to fnp_master_stat file");
        return;
    }

    // 添加定时器，定时检查frontend状态
    int timerfd = fnp_create_timerfd(5, true);
    if (timerfd < 0)
    {
        perror("fnp_create_timerfd");
        return;
    }
    master.timer_tag.kind = master_ev_kind_timer;
    master.timer_tag.fd = timerfd;
    fmsg_epoll_add_ptr(master.epoll_fd, timerfd, &master.timer_tag);
    if (master.retire_chan != NULL)
    {
        master.retire_tag.kind = master_ev_kind_retire;
        master.retire_tag.fd = master.retire_chan->event_fd;
        fmsg_epoll_add_ptr(master.epoll_fd, master.retire_chan->event_fd, &master.retire_tag);
    }

    while (1)
    {
        int n = epoll_wait(master.epoll_fd, evs, MAX_EVENTS, -1);
        bool retire_ready = false;
        for (int i = 0; i < n; i++)
        {
            struct epoll_event *ev = &evs[i];
            master_ev_tag_t *tag = (master_ev_tag_t *)ev->data.ptr;
            if (unlikely(tag == &master.timer_tag))
            {
                uint64_t expirations;
                read(timerfd, &expirations, sizeof(expirations)); // 清除定时器计数
                check_frontend_alive();
                write_worker_rx_info(fp);
                log_device_eth_stats_from_master();
                // check_daemon_info(fp);
                // show_all_fsocket();
            }
            else if (tag == &master.retire_tag)
            {
                retire_ready = true;
            }
            else
            {
                // 处理fsocket的eventfd事件
                fsocket_t *socket = (fsocket_t *)evs[i].data.ptr;

                eventfd_t value;
                eventfd_read(socket->tx_efd_in_backend, &value); // 清除事件fd计数

                handle_fsocket_event(socket, value);
            }
        }

        if (retire_ready)
        {
            drain_retired_sockets();
        }
    }
}

int compare_pid(void *v1, void *v2)
{
    fnp_frontend_t *f1 = (fnp_frontend_t *)v1;
    fnp_frontend_t *f2 = (fnp_frontend_t *)v2;
    return f1->pid - f2->pid;
}

int init_fnp_master()
{
    fnp_init_list(&master.frontend_list, compare_pid);
    master.epoll_fd = fmsg_epoll_create();
    if (master.epoll_fd < 0)
    {
        return FNP_ERR_MALLOC;
    }

    master.retire_chan = fchannel_create(1024);
    if (master.retire_chan == NULL)
    {
        return FNP_ERR_MALLOC;
    }

    int ret = rte_mp_action_register(FAPI_REGISTER_ACTION_NAME, register_frontend_action);
    if (ret != 0)
    {
        printf("fail to register action of %s\n", FAPI_REGISTER_ACTION_NAME);
        return ret;
    }

    ret = rte_mp_action_register(FAPI_CREATE_FSOCKET_ACTION_NAME, create_fsocket_action);
    if (ret != 0)
    {
        printf("fail to register action of %s\n", FAPI_CREATE_FSOCKET_ACTION_NAME);
        return ret;
    }

    ret = rte_mp_action_register(FAPI_ACCEPT_FSOCKET_ACTION_NAME, accept_fsocket_action);
    if (ret != 0)
    {
        printf("fail to register action of %s\n", FAPI_ACCEPT_FSOCKET_ACTION_NAME);
        return ret;
    }

    ret = rte_mp_action_register(FAPI_CLOSE_FSOCKET_ACTION_NAME, close_fsocket_action);
    if (ret != 0)
    {
        printf("fail to register action of %s\n", FAPI_CLOSE_FSOCKET_ACTION_NAME);
        return ret;
    }

    // pthread_t ctrl_thread;
    // ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_master_task", NULL,
    //                              fnp_master_loop, NULL);
    // if (ret != 0)
    // {
    //     printf("failed to create master thread\n");
    //     return ret;
    // }

    return FNP_OK;
}
