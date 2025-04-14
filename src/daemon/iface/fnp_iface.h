#ifndef FNP_IFACE_H
#define FNP_IFACE_H

#include "fnp_common.h"
#include "fnp_pring.h"

#include <rte_ether.h>

#define MAX_IFACE_NUM 8

typedef struct fnp_iface
{
    struct rte_ether_addr mac;
    u16 id;
    u32 ip;
    u32 mask;
    u32 gateway;
    fnp_pring *tx_queue;
} fnp_iface_t;

fnp_iface_t *lookup_iface(u32 ip);

u32 find_next_hop(fnp_iface_t *iface, u32 rip);

fnp_iface_t *find_iface_for_outlet(u32 rip);

#endif // FNP_IFACE_H
