#ifndef FNP_INIT_H
#define FNP_INIT_H

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_timer.h>
#include "fnp_common.h"
#include "fnp_ring.h"
#include "fnp_hash.h"

#define MAX_IFACES      8

typedef struct rte_mbuf rte_mbuf;

typedef struct fnp_iface {
    struct rte_ether_addr mac;
    u16 id;
    u32 ip;
    u32 mask;
    u32 gateway;
    fnp_ring_t* tx_queue;
    fnp_ring_t* rx_queue;
} fnp_iface_t;

typedef struct dpdk_conf {
    char* lcore_list;
    char* whitelist;
    u16 main_lcore;
    u16 promiscuous;
} dpdk_conf_t;



typedef struct fnp_conf {
    dpdk_conf_t dpdk;
    fnp_iface_t ifaces[MAX_IFACES];
    u16 ifaces_num;
    u16 worker1;
    u16 worker2;
    u16 worker3;
    struct rte_mempool* directPool;
    fnp_hash_t* tcpSockTbl;
    fnp_hash_t* arpTbl;
} fnp_conf_t ;


extern fnp_conf_t conf;


static inline rte_mbuf *fnp_alloc_mbuf()
{
    u32 count = rte_mempool_avail_count(conf.directPool);
    rte_mbuf* m = rte_pktmbuf_alloc(conf.directPool);

    if(m == NULL) {
        printf("count: %u\n",count);
        printf("error: rte_pktmbuf_alloc failed\n");
    }

    return m;

}

static inline void fnp_free_mbuf(rte_mbuf* m)
{
    rte_pktmbuf_free(m);
}

static inline fnp_iface_t *fnp_get_iface(u16 id)
{
    return &conf.ifaces[id];
}

#endif //FNP_INIT_H
