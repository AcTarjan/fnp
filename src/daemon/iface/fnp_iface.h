#ifndef FNP_IFACE_H
#define FNP_IFACE_H

#include "fnp_common.h"
#include "libfnp-conf.h"

#include <rte_ether.h>

#define MAX_IFACE_NUM 8
#define MAX_PORT_NUM 8

typedef struct fnp_iface
{
    u16 id;
    i32 port; //实际的物理网卡
    char* name;
    u32 ip;
    u32 mask;
    u32 gateway;
} fnp_iface_t;

struct rte_ether_addr* get_port_mac(int id);

fnp_iface_t* lookup_iface(u32 ip);

u32 find_next_hop(fnp_iface_t* iface, u32 rip);

fnp_iface_t* find_iface_for_outlet(u32 rip);

i32 init_fnp_iface_layer(fnp_config* conf);

#endif // FNP_IFACE_H
