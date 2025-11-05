#ifndef FNP_WORKER_H
#define FNP_WORKER_H

#include <rte_errno.h>
#include <rte_timer.h>

#include "hash.h"
#include "sys/epoll.h"
#include <rte_per_lcore.h>

#include "fnp_context.h"
#include "fnp_list.h"
#include "fnp_msg.h"
#include "fsocket.h"
#include "libfnp-conf.h"

#define FNP_MAX_PORTS 8

// 一个lcore对应一个worker
typedef struct fnp_worker
{
    i32 id;
    i32 queue_id; //网卡的queue_id, 等于worker_id
    i32 lcore_id; //所在的lcore
    i32 epoll_fd; // 监听socket的tx和net_rx事件
    rte_spinlock_t polling_lock; // polling_count的锁
    int polling_count; // 当前轮询的socket数量
    fsocket_t* polling_table[1024]; //正在轮询的fsocket列表
    struct rte_mempool* pool; //内存池
    struct rte_mempool* rx_pool; //接收内存池, 用于网卡接收数据包
    struct rte_mempool* clone_pool; //间接内存池, 用于clone
    fnp_ring_t* fmsg_ring; //当前worker的消息监听器
    fnp_ring_t* tx_ring; // 暂存需要发送的mbuf, 存储一定量后一起发送, 每个port存在一个, 目前仅支持一个port
    rte_hash* arp_table; //等待arp结果的待发送的mbuf列表, key为tip
} fnp_worker_t;

extern int fnp_worker_count; // worker的数量
extern fnp_worker_t workers[FNP_MAX_WORKER_NUM];

RTE_DECLARE_PER_LCORE(int, worker_id); /**< Per thread "lcore id". */

#define fnp_worker_id   RTE_PER_LCORE(worker_id)
#define get_local_worker()  &workers[fnp_worker_id]
#define get_fnp_worker(id)  &workers[(id)]

static void show_mempool_info()
{
    for (int i = 0; i < fnp_worker_count; i++)
    {
        fnp_worker_t* worker = get_fnp_worker(i);
        struct rte_mempool* mp = worker->pool;
        u32 count = rte_mempool_avail_count(mp);
        printf("%s have %d, avail count is %u\n", mp->name, mp->size, count);

        mp = worker->clone_pool;
        count = rte_mempool_avail_count(mp);
        printf("%s have %d, avail count is %u\n", mp->name, mp->size, count);

        mp = worker->rx_pool;
        count = rte_mempool_avail_count(mp);
        printf("%s have %d, avail count is %u\n", mp->name, mp->size, count);

        // struct rte_mempool_cache *cache;
        // for (int i = 1; i < 6; i++)
        // {
        //     cache = rte_mempool_default_cache(mp, i);
        //     if (cache != NULL)
        //     {
        //         FNP_INFO("lcore %u cache is %d\n", i, cache->len);
        //     }
        // }
    }
}


static inline struct rte_mbuf* clone_mbuf(struct rte_mbuf* md)
{
    fnp_worker_t* worker = get_local_worker();
    struct rte_mbuf* m = rte_pktmbuf_clone(md, worker->clone_pool);
    if (m == NULL)
    {
        /* code */
        // printf("rte_pktmbuf_clone failed: %s, mbuf: %p\n", rte_strerror(rte_errno), m);
        return NULL;
    }

    return m;
}

static inline struct rte_mbuf* alloc_mbuf()
{
    fnp_worker_t* worker = get_local_worker();
    struct rte_mbuf* m = rte_pktmbuf_alloc(worker->pool);
    if (m == NULL)
    {
        // printf("rte_pktmbuf_alloc failed: %s, mbuf: %p\n", rte_strerror(rte_errno), m);
        return NULL;
    }

    return m;
}

static inline void free_mbuf(struct rte_mbuf* m)
{
    rte_pktmbuf_free(m);
}

void fnp_worker_add_fsocket(fsocket_t* socket);

int init_fnp_worker(worker_config* conf);

int start_fnp_worker();

#endif // FNP_WORKER_H
