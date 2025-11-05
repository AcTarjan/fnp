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
RTE_DEFINE_PER_LCORE(uint64_t, tsc_cycles);

#define MBUF_BURST_SIZE 64
#define PORT_ID 0
#define PREFETCH_OFFSET 3

int fnp_worker_count = 0; // worker的数量
fnp_worker_t workers[FNP_MAX_WORKER_NUM];

// 目前最大的协议值 + 1
static fsocket_polling_func fsocket_polling_handlers[fnp_protocol_udp + 1];

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
    static struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {0};

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

void fnp_worker_add_fsocket(fsocket_t* socket)
{
    int worker_id = 0;
    fnp_worker_t* worker = get_fnp_worker(worker_id);
    socket->polling_worker = worker_id;
    // TODO: 负载均衡以及polling_table满的处理
    rte_spinlock_lock(&worker->polling_lock);
    worker->polling_table[worker->polling_count++] = socket;
    rte_spinlock_unlock(&worker->polling_lock);
}

static inline void worker_handle_polling(fnp_worker_t* worker, u64 tsc)
{
    int size = worker->polling_count;
    for (int i = 0; i < size; i++)
    {
        fsocket_t* socket = worker->polling_table[i];
        fsocket_polling_handlers[socket->proto](socket, tsc); // 执行polling处理函数
        if (unlikely(tsc - socket->polling_tsc > RTE_PER_LCORE(tsc_cycles))) // 长时间没有数据, 不再polling
        {
            printf("remove fsocket from worker\n");
            rte_spinlock_lock(&worker->polling_lock);
            worker->polling_count--; // 减少一个数据, 正好当下标
            worker->polling_table[i] = worker->polling_table[worker->polling_count]; // 用最后一个替换当前位置
            rte_spinlock_unlock(&worker->polling_lock);
            socket->polling_worker = -1; // 标记为不在polling队列中
            size--; // 数量减少
        }
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
    u64 hz = fnp_get_tsc_hz();
    RTE_PER_LCORE(tsc_cycles) = hz;
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

        // 处理polling
        worker_handle_polling(worker, cur_tsc);

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

        worker->polling_count = 0;
        rte_spinlock_init(&worker->polling_lock);

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
    fsocket_polling_handlers[fnp_protocol_tcp] = tcp_handle_fsocket_event;
    fsocket_polling_handlers[fnp_protocol_udp] = udp_polling_fsocket;
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
