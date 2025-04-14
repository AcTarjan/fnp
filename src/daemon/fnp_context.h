#ifndef FNP_CONTEXT_H
#define FNP_CONTEXT_H

#include "fnp_common.h"
#include "fnp_pring.h"
#include "hash.h"
#include "fnp_iface.h"
#include "libfnp-conf.h"

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_timer.h>
#include <rte_errno.h>

typedef struct fnp_context
{
    fnp_config conf;
    fnp_iface_t ifaces[MAX_IFACE_NUM];
    u32 iface_num;
    struct rte_mempool *pool2;
    struct rte_mempool *pool5;
    struct rte_mempool *clone_pool;
    struct rte_mempool *rx_pool;
    rte_hash *frontendTbl;
    rte_hash *arpTbl;
    rte_hash *sockTbl;
} fnp_context;

extern fnp_context fnp;

i32 init_fnp_daemon(char *path);

static void show_mempool_info()
{
    struct rte_mempool *mp = fnp.pool2;
    u32 count = rte_mempool_avail_count(mp);
    printf("%s avail count is %u\n", mp->name, count);

    mp = fnp.pool5;
    count = rte_mempool_avail_count(mp);
    printf("%s avail count is %u\n", mp->name, count);

    mp = fnp.clone_pool;
    count = rte_mempool_avail_count(mp);
    printf("%s avail count is %u\n", mp->name, count);

    mp = fnp.rx_pool;
    count = rte_mempool_avail_count(mp);
    printf("%s avail count is %u\n", mp->name, count);
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

static inline struct rte_mbuf *clone_mbuf(struct rte_mbuf *md)
{
    struct rte_mbuf *m = rte_pktmbuf_clone(md, fnp.clone_pool);
    if (m == NULL)
    {
        /* code */
        printf("rte_pktmbuf_alloc failed: %s, mbuf: %p\n", rte_strerror(rte_errno), m);
        show_mempool_info();
    }

    return m;
}

struct rte_mbuf *alloc_mbuf();

static inline void free_mbuf(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m);
}

#endif // FNP_CONTEXT_H
