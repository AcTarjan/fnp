#include "fnp_worker.h"
#include "fnp_msg.h"
#include "fnp_context.h"
#include "fnp_network.h"
#include "fnp_ring.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <rte_per_lcore.h>
#include <unistd.h>

#include "udp.h"
#include "arp.h"

// 每个lcore线程会拥有一个id实例
RTE_DEFINE_PER_LCORE(int, worker_id);
RTE_DEFINE_PER_LCORE(uint64_t, tsc_cycles);

#define MBUF_BURST_SIZE 64

int get_fnp_worker_count(void)
{
    return fnp.worker.count;
}

fnp_worker_t* get_local_worker(void)
{
    return get_fnp_worker(fnp_worker_id);
}

fnp_worker_t* get_fnp_worker(int id)
{
    if (unlikely(id < 0 || id >= fnp.worker.count))
    {
        return NULL;
    }

    return &fnp.worker.workers[id];
}

static void recv_data_from_nic()
{
    fnp_worker_t* worker = get_local_worker();

    for (int dev_index = 0; dev_index < get_fnp_device_count(); ++dev_index)
    {
        fnp_device_t* dev = get_fnp_device(dev_index);
        if (dev == NULL || dev->ops == NULL || dev->ops->recv == NULL)
        {
            continue;
        }

        dev->ops->recv(dev, worker->queue_id, MBUF_BURST_SIZE);
    }
}

static void send_data_to_net()
{
    fnp_worker_t* worker = get_local_worker();
    static struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {0};

    while (1)
    {
        u32 txNum = fnp_ring_dequeue_burst(worker->tx_ring, (void**)mbufs, MBUF_BURST_SIZE);
        if (txNum > 0)
        {
            u32 offset = 0;
            while (offset < txNum)
            {
                u16 port_id = mbufs[offset]->port;
                u32 burst = 1;
                while (offset + burst < txNum && mbufs[offset + burst]->port == port_id)
                {
                    ++burst;
                }

                fnp_device_t* dev = lookup_device_by_port(port_id);
                if (dev == NULL || dev->ops == NULL || dev->ops->send == NULL)
                {
                    rte_pktmbuf_free_bulk(&mbufs[offset], burst);
                    offset += burst;
                    continue;
                }

                i32 sent = dev->ops->send(dev, worker->queue_id, &mbufs[offset], burst);
                if (sent < (i32)burst)
                {
                    printf("device tx warning! port=%u, txNum=%u, tx_burst=%d\n", port_id, burst, sent);
                    rte_pktmbuf_free_bulk(&mbufs[offset + sent], burst - sent);
                }
                offset += burst;
            }
        }
        if (txNum < MBUF_BURST_SIZE) // 说明没有数据了
            break;
    }
}

void fnp_worker_add_fsocket(fsocket_t* socket)
{
    int worker_id = 0;
    fnp_worker_t* worker = get_fnp_worker(worker_id);
    if (worker == NULL)
    {
        return;
    }

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
        const fsocket_ops_t* ops = get_fsocket_ops(socket->type);
        fsocket_send_func send = ops == NULL ? NULL : ops->send;
        if (likely(send != NULL))
        {
            send(socket, tsc); // 执行发送轮询
        }
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

        // 收取底层device上的报文，并在device接收入口内完成协议分发
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
    }
}

int init_fnp_worker(worker_config* conf)
{
    fnp.worker.count = conf->lcores_count;
    printf("fnp_worker_count = %d\n", fnp.worker.count);
    for (int id = 0; id < fnp.worker.count; id++)
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
        worker->arp_table = hash_create(arp_name, 256, sizeof(arp_key_t));
        if (worker->arp_table == NULL)
        {
            return FNP_ERR_CREATE_HASH_TABLE;
        }

        worker->epoll_fd = fmsg_epoll_create();
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
                                               FNP_MBUFPOOL_PRIV_SIZE,
                                               RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE, socket_id);
        if (worker->pool == NULL)
        {
            printf("%d create gDirectPool failed! rte_errno=%d(%s), socket_id=%d, pool_size=%d\n",
                   id, rte_errno, rte_strerror(rte_errno), socket_id, conf->mbuf_pool_size);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char rx_pool_name[32] = {0};
        sprintf(rx_pool_name, "worker%d_rx_pool", id);
        worker->rx_pool = rte_pktmbuf_pool_create(rx_pool_name, conf->rx_pool_size, 0,
                                                  FNP_MBUFPOOL_PRIV_SIZE,
                                                  RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE, socket_id);
        if (worker->rx_pool == NULL)
        {
            printf("create rx pool failed! rte_errno=%d(%s), socket_id=%d, pool_size=%d\n",
                   rte_errno, rte_strerror(rte_errno), socket_id, conf->rx_pool_size);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char clone_pool_name[32] = {0};
        sprintf(clone_pool_name, "worker%d_clone_pool", id);
        worker->clone_pool = rte_pktmbuf_pool_create(clone_pool_name, conf->clone_pool_size, 0,
                                                     FNP_MBUFPOOL_PRIV_SIZE,
                                                     RTE_MBUF_DEFAULT_BUF_SIZE - FNP_MBUFPOOL_PRIV_SIZE, socket_id);
        if (worker->clone_pool == NULL)
        {
            printf("create clone pool failed! rte_errno=%d(%s), socket_id=%d, pool_size=%d\n",
                   rte_errno, rte_strerror(rte_errno), socket_id, conf->clone_pool_size);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        worker->tx_ring = fnp_ring_create(conf->tx_ring_size, false, false);
        if (worker->tx_ring == NULL)
        {
            printf("create tx_queue error! tx_ring_size=%d, fnp_ring_create requires a power-of-two size\n",
                   conf->tx_ring_size);
            return FNP_ERR_CREATE_RING;
        }
    }

    FNP_INFO("fnp_worker init successfully\n");
    return FNP_OK;
}

int start_fnp_worker()
{
    for (int id = 0; id < fnp.worker.count; id++)
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
