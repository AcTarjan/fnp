#ifndef FNP_ROUTE_H
#define FNP_ROUTE_H

#include "fnp_network.h"

typedef enum fnp_route_type
{
    fnp_route_type_connected = 1,
    fnp_route_type_gateway,
} fnp_route_type_t;

typedef struct route_entry
{
    u32 prefix_be;
    u32 mask_be;
    u8 prefix_len;
    u8 reserved0;
    u16 reserved1;
    u32 next_hop_be;
    fnp_route_type_t type;
    fnp_ifaddr_t* ifaddr;
} route_entry_t;

typedef struct fnp_route_result
{
    bool is_local;
    fnp_ifaddr_t* ifaddr;
    u32 next_hop_be;
    u32 pref_src_be;
} fnp_route_result_t;

int init_route_layer(fnp_config* conf);

fnp_ifaddr_t* route_lookup_local(u32 local_ip_be);

int route_lookup(u32 dst_ip_be, fnp_route_result_t* result);

int route_lookup_with_ifaddr(fnp_ifaddr_t* preferred_ifaddr, u32 dst_ip_be, fnp_route_result_t* result);

#endif // FNP_ROUTE_H
