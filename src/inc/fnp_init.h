#ifndef FNP_INIT_H
#define FNP_INIT_H

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_timer.h>
#include "fnp_common.h"
#include "fnp_ring.h"
#include "fnp_pring.h"
#include "hash.h"
#include "libfnp-conf.h"

#define MAX_IFACES      8

typedef struct rte_mbuf rte_mbuf;

typedef struct {
    struct rte_ether_addr mac;
    u16 id;
    u32 ip;
    u32 mask;
    u32 gateway;
    fnp_pring* tx_queue;
    fnp_pring* rx_queue;
} fnp_iface;


typedef struct {
    fnp_config conf;
    fnp_iface ifaces[MAX_IFACES];
    struct rte_mempool* pool;
    rte_hash* arpTbl;
    rte_hash* tcpTbl;
    rte_hash* udpTbl;
} fnp_context;


extern fnp_context fnp;


static inline rte_mbuf *fnp_mbuf_alloc()
{
    rte_mbuf* m = rte_pktmbuf_alloc(fnp.pool);
    if(m == NULL) {
        u32 count = rte_mempool_avail_count(fnp.pool);
        printf("avail count: %u\n",count);
        printf("error: rte_pktmbuf_alloc failed\n");
    }

    return m;
}

static inline void fnp_mbuf_free(rte_mbuf* m)
{
    rte_pktmbuf_free(m);
}

static inline fnp_iface *fnp_iface_get(u16 id)
{
    return &fnp.ifaces[id];
}

#endif //FNP_INIT_H
