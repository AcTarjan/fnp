#include "fnp_worker.h"
#include "fnp_msg.h"
#include "ether.h"
#include "fnp_context.h"
#include "fnp_ring.h"

#include "tcp_sock.h"
#include <rte_ethdev.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <rte_per_lcore.h>
#include <unistd.h>

#include "udp.h"
#include "arp.h"
#include "quic.h"
#include "tcp.h"

// 每个lcore线程会拥有一个id实例
RTE_DEFINE_PER_LCORE(int, worker_id);

#define MBUF_BURST_SIZE 64
#define PORT_ID 0
#define PREFETCH_OFFSET 3

int fnp_worker_count = 0; // worker的数量
fnp_worker_t workers[FNP_MAX_WORKER_NUM];

// 目前最大的协议值 + 1
static fsocket_event_handler_func fsocket_handlers[fnp_protocol_udp + 1];

static void recv_data_from_nic()
{
    fnp_worker_t* worker = get_local_worker();
    struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {0};
    /*** recv from nic ***/
    i32 rxNum = rte_eth_rx_burst(PORT_ID, worker->queue_id, mbufs, MBUF_BURST_SIZE);
    for (i32 i = 0; i < rxNum; ++i)
    {
        ether_recv_mbuf(mbufs[i]);
    }
}

static void send_data_to_net()
{
    fnp_worker_t* worker = get_local_worker();
    struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {0};

    while (1)
    {
        u32 txNum = fnp_ring_dequeue_burst(worker->tx_ring, mbufs, MBUF_BURST_SIZE);
        if (txNum > 0)
        {
            i32 num = rte_eth_tx_burst(PORT_ID, worker->queue_id, mbufs, txNum);
            if (num < txNum)
            {
                printf("rte_eth_tx_burst warning! txNum: %d, tx_burst: %d\n", txNum, num);
                rte_pktmbuf_free_bulk(&mbufs[num], txNum - num);
                break;
            }
        }
        if (txNum < MBUF_BURST_SIZE) // 说明没有数据了
            break;
    }
}

static inline void fnp_epoll_wait_fsocket(int epoll_fd)
{
#define MAX_EVENTS 32
    static struct epoll_event evs[MAX_EVENTS];

    // 不能阻塞，因为需要轮询网卡
    int n = epoll_wait(epoll_fd, evs, MAX_EVENTS, 0);
    for (int i = 0; i < n; i++)
    {
        eventfd_t value;
        struct epoll_event* ev = &evs[i];
        fsocket_t* socket = (fsocket_t*)ev->data.ptr;
        int fd = socket->tx_efd_in_backend;
        // eventfd_read(fd, &value);   //即使不清零，每次eventfd_wirite也会触发
        fsocket_handlers[socket->proto](socket, value);
    }
}

static inline void handle_worker_fmsg(fnp_worker_t* worker)
{
    fnp_msg_t* msg;
    // 遍历来自master的消息，少量
    while (fnp_ring_dequeue(worker->fmsg_ring, (void**)&msg) != 0)
    {
        if (msg->type == fmsg_type_connect_fsocket)
        {
            // tcp_connect(msg->ptr);
        }
        else if (msg->type == fmsg_type_close_fsocket)
        {
            // tcp_close(msg->ptr);
        }

        fnp_free(msg);
    }
}

// 尽量避免遍历，选择epoll来处理事件通知
// 尽量不要将mbuf保存在ofo队列或者pending队列内部，避免mbuf池耗尽
int fnp_worker_loop(void* arg)
{
    int id = *(int*)arg;
    RTE_PER_LCORE(worker_id) = id; //初始化线程变量
    fnp_worker_t* worker = get_local_worker();

    i32 socket_id = rte_socket_id();
    i32 lcore_id = rte_lcore_id();
    printf("fnp_worker %d is running: lcore %d in socket %d\n", fnp_worker_id, lcore_id, socket_id);
    u64 cur_tsc, prev_tsc = 0;
    u64 hz = fnp_get_tsc_hz(); // 10ms
    u64 timer_timeout = hz / 1000; // 1ms
    while (1)
    {
        cur_tsc = fnp_get_tsc();

        // 收到网卡的数据，会改变TCP的状态
        recv_data_from_nic();

        //  每1ms检查定时器状态
        if (unlikely(cur_tsc - prev_tsc > timer_timeout))
        {
            rte_timer_manage(); // 检查定时器，触发重传
            prev_tsc = cur_tsc;
        }

        // 处理fsocket的应用层/网络层数据
        fnp_epoll_wait_fsocket(worker->epoll_fd);

        // 从网卡向网络发送数据
        send_data_to_net();

        // 处理来自master的消息
        handle_worker_fmsg(worker);
    }
}

int init_fnp_worker(worker_config* conf)
{
    fnp_worker_count = conf->lcores_count;
    printf("fnp_worker_count = %d\n", fnp_worker_count);
    for (int id = 0; id < fnp_worker_count; id++)
    {
        fnp_worker_t* worker = get_fnp_worker(id);
        worker->id = id;
        worker->queue_id = id;
        worker->lcore_id = conf->lcores[id];
        i32 socket_id = (i32)rte_lcore_to_socket_id(worker->lcore_id);

        // 初始化socket表
        fnp_init_list(&worker->quic_list, NULL);

        //初始化arp pending table
        char arp_name[32] = {0};
        sprintf(arp_name, "worker%d_arp_tbl", id);
        worker->arp_table = hash_create(arp_name, 256, sizeof(u32));
        if (worker->arp_table == NULL)
        {
            return FNP_ERR_CREATE_HASH_TABLE;
        }

        worker->epoll_fd = fnp_epoll_create();
        if (worker->epoll_fd < 0)
        {
            printf("create epoll fd failed!\n");
            return FNP_ERR_CREATE_EPOLL;
        }

        worker->fmsg_ring = fnp_ring_create(64, true, false);
        if (worker->fmsg_ring == NULL)
        {
            return FNP_ERR_GENERIC;
        }

        char pool_name[32] = {0};
        sprintf(pool_name, "worker%d_mbuf_pool", id);
        worker->pool = rte_pktmbuf_pool_create(pool_name, conf->mbuf_pool_size, 0,
                                               FNP_MBUFPOOL_PRIV_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (worker->pool == NULL)
        {
            printf("%d create gDirectPool failed!\n", id);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char rx_pool_name[32] = {0};
        sprintf(rx_pool_name, "worker%d_rx_pool", id);
        worker->rx_pool = rte_pktmbuf_pool_create(rx_pool_name, conf->rx_pool_size, 0,
                                                  FNP_MBUFPOOL_PRIV_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (worker->rx_pool == NULL)
        {
            printf("create rx pool failed!\n");
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char clone_pool_name[32] = {0};
        sprintf(clone_pool_name, "worker%d_clone_pool", id);
        worker->clone_pool = rte_pktmbuf_pool_create(clone_pool_name, conf->clone_pool_size, 0,
                                                     FNP_MBUFPOOL_PRIV_SIZE, 0, socket_id);
        if (worker->clone_pool == NULL)
        {
            printf("create clone pool failed!\n");
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        worker->tx_ring = fnp_ring_create(conf->tx_ring_size, false, false);
        if (worker->tx_ring == NULL)
        {
            printf("create tx_queue error!\n");
            return FNP_ERR_CREATE_RING;
        }
    }

    FNP_INFO("fnp_worker init successfully\n");
    return FNP_OK;
}

int start_fnp_worker()
{
    fsocket_handlers[fnp_protocol_tcp] = tcp_handle_fsocket_event;
    fsocket_handlers[fnp_protocol_udp] = udp_handle_fsocket_event;
    for (int id = 0; id < fnp_worker_count; id++)
    {
        fnp_worker_t* worker = get_fnp_worker(id);
        if (rte_eal_remote_launch(fnp_worker_loop, &worker->id, worker->lcore_id) != 0)
        {
            printf("launch %d error!\n", worker->lcore_id);
            return -1;
        }
    }

    return 0;
}
