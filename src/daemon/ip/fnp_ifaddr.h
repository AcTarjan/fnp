#ifndef FNP_IFADDR_H
#define FNP_IFADDR_H

#include "fnp_device.h"

#include <rte_hash.h>

#define FNP_MAX_NETWORK_NUM FNP_NETWORK_MAX
#define FNP_MAX_IFADDR_NUM (FNP_NETWORK_MAX * FNP_INIT_IFADDR_MAX)

typedef struct fnp_ifaddr fnp_ifaddr_t;
typedef struct fnp_ifaddr_pool fnp_ifaddr_pool_t;

struct fnp_ifaddr_pool
{
    u16 id;
    fnp_device_t *dev;
    char name[FNP_NETWORK_NAME_LEN];
    u32 subnet_be;
    u32 netmask_be;
    u32 gateway_be;
    u8 prefix_len;
    u8 reserved0;
    u16 next_ifaddr_seq;
    u32 next_ip_cpu;
    i32 priority;
};

struct fnp_ifaddr
{
    u16 id;
    u16 pool_id;
    fnp_device_t *dev;
    char *name;
    char *ip;
    char pool_name[FNP_NETWORK_NAME_LEN];
    u32 local_ip_be;
    u32 netmask_be;
    u32 network_be;
    u32 gateway_be;
    u8 prefix_len;
};

typedef struct fnp_ifaddr_context
{
    int pool_count;
    fnp_ifaddr_pool_t pools[FNP_MAX_NETWORK_NUM];
    int ifaddr_count;
    fnp_ifaddr_t ifaddrs[FNP_MAX_IFADDR_NUM];
    struct rte_hash *ifaddr_tbl;
} fnp_ifaddr_context_t;

int init_fnp_ifaddr_layer(fnp_config *conf);

int get_fnp_ifaddr_count(void);

fnp_ifaddr_t *get_fnp_ifaddr(int index);

fnp_ifaddr_t *lookup_ifaddr(u32 local_ip_be);

fnp_ifaddr_t *lookup_ifaddr_by_id(u16 ifaddr_id);

fnp_ifaddr_t *find_ifaddr_on_device(fnp_device_t *dev, u32 local_ip_be);

fnp_ifaddr_t *find_ifaddr_on_device_for_remote(fnp_device_t *dev, u32 remote_ip_be);

int export_fnp_ifaddrs(fnp_ifaddr_info_t *infos, u16 info_capacity, u16 *info_count);

static inline bool is_local_ipaddr(u32 ip)
{
    return lookup_ifaddr(ip) != NULL;
}

#endif // FNP_IFADDR_H
