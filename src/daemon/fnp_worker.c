#include "fnp_worker.h"
#include "fnp_msg.h"
#include "ether.h"
#include "fnp_context.h"
#include "fnp_socket.h"
#include "fnp_pring.h"

#include "tcp_sock.h"
#include <rte_ethdev.h>
#include <sys/epoll.h>

#include <rte_per_lcore.h>
#include <unistd.h>

#include "arp.h"
#include "quic.h"

// 每个lcore线程会拥有一个id实例
RTE_DEFINE_PER_LCORE(int, worker_id);

#define MBUF_BURST_SIZE 64
#define PORT_ID 0
#define PREFETCH_OFFSET 3

int fnp_worker_count = 0; // worker的数量
fnp_worker_t workers[FNP_MAX_WORKER_NUM];

static void worker_add_socket(fnp_worker_t* worker, fsocket_t* socket)
{
    fnp_list_insert(&worker->socket_list, &socket->worker_node, socket);
}

void remove_socket_from_worker(fsocket_t* socket)
{
    if (socket->worker_id == FNP_MAX_WORKER_NUM)
    {
        // tcp server socket不需要从worker中删除
        return;
    }

    fnp_worker_t* worker = get_fnp_worker(socket->worker_id);

    fnp_list_delete(&worker->socket_list, &socket->worker_node);
}

int dispatch_socket_to_worker(fsocket_t* socket, int worker_id)
{
    // tcp server socket和本地通信socket不需要分配到worker
    if (is_tcp_server_socket(socket) || socket->is_local_communication)
    {
        socket->worker_id = FNP_MAX_WORKER_NUM;
        socket->pool = (get_fnp_worker(0))->pool;
        return FNP_OK;
    }

    fnp_worker_t* worker = NULL;
    // master创建的socket
    if (worker_id < 0)
    {
        // TODO: 负载均衡
        worker_id = 0;
        worker = get_fnp_worker(worker_id);

        fnp_msg_t* msg = new_fmsg(fnp_master_id, fmsg_type_add_socket);
        if (msg == NULL)
        {
            return FNP_ERR_MALLOC;
        }

        msg->ptr = socket;
        send_fmsg(worker_id, msg);
    }
    else
    {
        worker = get_fnp_worker(worker_id);
        worker_add_socket(worker, socket);
    }


    socket->worker_id = worker_id;
    socket->pool = worker->pool;

    return FNP_OK;
}

static void recv_data_from_net()
{
    fnp_worker_t* worker = get_local_worker();
    struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {0};
    i64 count = 0;
    /*** recv from nic ***/
    i32 rxNum = rte_eth_rx_burst(PORT_ID, worker->queue_id, mbufs, MBUF_BURST_SIZE);
    for (i32 i = 0; i < rxNum; ++i)
    {
        count++;
        if (count % 100 == 0) // 人为丢包
        {
            printf("recv mbuf packet in %d: %lld\n", worker->id, count);
        }
        ether_recv_mbuf(mbufs[i]);
    }
}

static void send_data_to_net()
{
    fnp_worker_t* worker = get_local_worker();
    struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {0};

    while (1)
    {
        i32 txNum = fnp_pring_dequeue_bulk(worker->tx_ring, mbufs, MBUF_BURST_SIZE);
        if (txNum > 0)
        {
            i32 num = rte_eth_tx_burst(PORT_ID, worker->queue_id, mbufs, txNum);
            if (num < txNum)
            {
                printf("txNum: %d, tx_burst: %d\n", txNum, num);
                rte_pktmbuf_free_bulk(&mbufs[num], txNum - num);
            }
        }
        if (txNum < MBUF_BURST_SIZE) // 说明没有数据了
            break;
    }
}


static void handle_create_stream_fmsg(fnp_msg_t* msg)
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

    send_fmsg_reply(msg);
}

static void handle_create_cnx_fmsg(fnp_msg_t* msg)
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

    send_fmsg_reply(msg);
}

static void handle_worker_fmsg(fnp_msg_t* msg)
{
    fnp_worker_t* worker = get_local_worker();
    switch (msg->type)
    {
    case fmsg_type_add_socket:
        {
            worker_add_socket(worker, (fsocket_t*)msg->ptr);
            fnp_free(msg);
            break;
        }
    case fmsg_type_create_cnx:
        {
            handle_create_cnx_fmsg(msg);
            break;
        }
    case fmsg_type_create_stream:
        {
            handle_create_stream_fmsg(msg);
            break;
        }
    }
}

static void worker_handle_local_socket()
{
    fnp_worker_t* worker = get_local_worker();

    fnp_list_node_t* node = fnp_list_first(&worker->socket_list);
    while (node != NULL)
    {
        fsocket_t* socket = node->value;
        // 可能会删除当前socket, 提前保存下一个socket
        fnp_list_node_t* next_node = fnp_list_get_next(node);
        socket->handler(socket);
        node = next_node;
    }
}

int fnp_worker_loop(void* arg)
{
    int id = *(int*)arg;
    RTE_PER_LCORE(worker_id) = id; //初始化线程变量
    fnp_worker_t* worker = get_local_worker();

    i32 socket_id = rte_socket_id();
    i32 lcore_id = rte_lcore_id();
    printf("fnp_worker %d is running: lcore %d in socket %d\n", fnp_worker_id, lcore_id, socket_id);
    u64 cur_tsc, mem_prev_tsc = 0, prev_tsc = 0;
    u64 hz = rte_get_timer_hz(); // 10ms

    while (1)
    {
        cur_tsc = rte_rdtsc();

        // 收到网卡的数据，会改变TCP的状态
        recv_data_from_net();

        arp_handle_local_pending();

        // 每1ms检查定时器状态
        if (cur_tsc - prev_tsc > hz / 1000)
        {
            rte_timer_manage(); // 检查定时器，触发重传
            prev_tsc = cur_tsc;
        }

        // 检查mempool, 每5s检查一次
        if (cur_tsc - mem_prev_tsc > hz * 5)
        {
            // show_mempool_info();
            mem_prev_tsc = cur_tsc;
            struct rte_eth_stats stats;
            rte_eth_stats_get(0, &stats);
            printf("recv %llu packets from worker %d\n",
                   stats.q_ipackets[worker->id], worker->id);
        }

        // 处理收到的fmsg消息
        fmsg_listener_wait(worker->listener, handle_worker_fmsg);

        // 放在重传定时器后面，snd_nxt变小后，在该函数下执行重传动作。
        worker_handle_local_socket();

        // 从网卡向网络发送数据
        send_data_to_net();
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
        fnp_init_list(&worker->socket_list, NULL);

        //初始化arp pending table
        char arp_name[32] = {0};
        sprintf(arp_name, "worker%d_arp_tbl", id);
        worker->arp_table = hash_create(arp_name, 256, sizeof(u32));
        if (worker->arp_table == NULL)
        {
            return FNP_ERR_CREATE_HASH_TABLE;
        }


        worker->listener = register_fmsg_listener(id);
        if (worker->listener == NULL)
        {
            return FNP_ERR_GENERIC;
        }

        char pool_name[32] = {0};
        sprintf(pool_name, "worker%d_mbuf_pool", id);

#define MBUFPOOL_PRIV_SIZE 256
        worker->pool = rte_pktmbuf_pool_create(pool_name, conf->mbuf_pool_size, 0,
                                               MBUFPOOL_PRIV_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (worker->pool == NULL)
        {
            printf("%d create gDirectPool failed!\n", id);
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char rx_pool_name[32] = {0};
        sprintf(rx_pool_name, "worker%d_rx_pool", id);
        worker->rx_pool = rte_pktmbuf_pool_create(rx_pool_name, conf->rx_pool_size, 0,
                                                  0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (worker->rx_pool == NULL)
        {
            printf("create rx pool failed!\n");
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        char clone_pool_name[32] = {0};
        sprintf(clone_pool_name, "worker%d_clone_pool", id);
        worker->clone_pool = rte_pktmbuf_pool_create(clone_pool_name, conf->clone_pool_size, 0,
                                                     MBUFPOOL_PRIV_SIZE, 0, socket_id);
        if (worker->clone_pool == NULL)
        {
            printf("create clone pool failed!\n");
            return FNP_ERR_CREATE_MBUFPOOL;
        }

        worker->tx_ring = fnp_pring_create(conf->tx_ring_size);
        if (worker->tx_ring == NULL)
        {
            printf("create tx_queue error!\n");
            return -1;
        }
    }

    FNP_INFO("fnp_worker init successfully\n");
    return FNP_OK;
}

int start_fnp_worker()
{
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
