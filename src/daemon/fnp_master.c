#include "fnp_master.h"
#include "fnp_frontend.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "fnp_worker.h"
#include "fnp_api.h"
#include "fapi.h"
#include "hash.h"
#include "quic.h"
#include "tcp.h"

#include <rte_ethdev.h>

#include <unistd.h>


fmaster_context_t master;

// main lcore调用，检查fnp-frontend是否正常
// daemon的控制线程添加frontendTbl
static void check_frontend_alive()
{
    fnp_list_node_t* node = fnp_list_first(&master.frontend_list);
    while (node != NULL)
    {
        fnp_frontend_t* frontend = node->value;
        fnp_list_node_t* next_node = fnp_list_get_next(node);
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

                // 释放该前端所有的socket
                for (int i = 0; i < 1024; i++)
                {
                    fsocket_t* socket = frontend->fd_table[i];
                    if (socket != NULL)
                    {
                        free_fsocket(socket);
                    }
                }

                // 删除该前端
                frontend_free(frontend);
            }
        }
        node = next_node;
    }
}

static inline void handle_create_stream_fmsg(fnp_msg_t* msg)
{
    create_stream_param_t* param = msg->data;
    quic_stream_t* stream = quic_create_local_stream(param->cnx, param->is_unidir, param->priority);
    if (stream == NULL)
    {
        msg->code = FNP_ERR_CREATE_SOCKET;
    }
    else
    {
        msg->code = FNP_OK;
        msg->ptr = stream;
    }

    fmsg_send_reply(msg);
}

static inline void handle_create_cnx_fmsg(fnp_msg_t* msg)
{
    create_quic_cnx_param_t* param = msg->data;
    quic_cnx_t* cnx = quic_create_client_cnx(param->quic, &param->remote);
    if (cnx == NULL)
    {
        msg->code = FNP_ERR_CREATE_SOCKET;
    }
    else
    {
        msg->code = FNP_OK;
        msg->ptr = cnx;
    }

    fmsg_send_reply(msg);
}


static void check_daemon_info(FILE* fp)
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


int fnp_master_add_fsocket(fsocket_t* socket)
{
    int fd = socket->tx_efd_in_backend;
    struct epoll_event ev = {0}; // 注意，必须初始化为0，否则read value会有异常
    ev.events = EPOLLIN | EPOLLET; // 边沿触发，正常是指0到非0值才会触发，与epoll配合后，值变化就会触发
    ev.data.ptr = (void*)socket;
    // 注意ev.data是一个union，ptr,fd,u32和u64只能设置一个值。

    int ret = epoll_ctl(master.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    if (ret != 0)
    {
        return FNP_ERR_ADD_EVENTFD;
    }

    return FNP_OK;
}


static void handle_fsocket_event(fsocket_t* socket, u64 event)
{
    // 有数据要发送
    if (likely(event < fsocket_event_close))
    {
        if (socket->polling_worker < 0)
        {
            printf("add fsocket to worker for sending data\n");
            fnp_worker_add_fsocket(socket);
        }
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
    FILE* fp = fopen("./fnp_master_stat.txt", "w");
    if (fp == NULL)
    {
        perror("Failed to fnp_master_stat file");
        return;
    }

    // 添加定时器，定时检查frontend状态
    int timerfd = fnp_create_timerfd(5, true);
    fnp_epoll_add(master.epoll_fd, timerfd);

    while (1)
    {
        int n = epoll_wait(master.epoll_fd, evs, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++)
        {
            struct epoll_event* ev = &evs[i];
            if (unlikely(ev->data.fd == timerfd))
            {
                uint64_t expirations;
                read(timerfd, &expirations, sizeof(expirations)); //清除定时器计数
                check_frontend_alive();
                // check_daemon_info(fp);
                // show_all_fsocket();
            }
            else
            {
                // 处理fsocket的eventfd事件
                fsocket_t* socket = (fsocket_t*)evs[i].data.ptr;

                eventfd_t value;
                eventfd_read(socket->tx_efd_in_backend, &value); //清除事件fd计数

                // UDP, TCP, QUIC有不同的事件处理方式
                handle_fsocket_event(socket, value);
            }
        }
    }
}

int compare_pid(void* v1, void* v2)
{
    fnp_frontend_t* f1 = (fnp_frontend_t*)v1;
    fnp_frontend_t* f2 = (fnp_frontend_t*)v2;
    return f1->pid - f2->pid;
}

int init_fnp_master()
{
    fnp.sockTbl = create_socket_table();
    if (fnp.sockTbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    fnp_init_list(&master.frontend_list, compare_pid);
    master.epoll_fd = fnp_epoll_create();
    if (master.epoll_fd < 0)
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
