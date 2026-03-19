#ifndef FNP_NETWORK_H
#define FNP_NETWORK_H

#include "fnp_common.h"
#include "libfnp-conf.h"

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_mbuf.h>

#define FNP_MAX_DEVICE_NUM FNP_DEVICE_MAX
#define FNP_MAX_IFADDR_NUM (FNP_DEVICE_MAX * FNP_DEVICE_IFADDR_MAX)

typedef enum fnp_device_type
{
    fnp_device_type_physical = 1,
    fnp_device_type_tap,
} fnp_device_type_t;

typedef struct fnp_device fnp_device_t;
typedef struct fnp_ifaddr fnp_ifaddr_t;

typedef int (*fnp_device_init_func)(fnp_device_t* dev, const fnp_device_config* conf, int nb_queues);
typedef u16 (*fnp_device_recv_func)(fnp_device_t* dev, u16 queue_id, u16 budget);
typedef u16 (*fnp_device_send_func)(fnp_device_t* dev, u16 queue_id, struct rte_mbuf** mbufs, u16 count);

typedef struct fnp_device_ops
{
    fnp_device_init_func init;
    fnp_device_recv_func recv;
    fnp_device_send_func send;
} fnp_device_ops_t;

struct fnp_device
{
    u16 id;
    u16 port_id; // DPDK分配的port编号，从0开始
    char name[32];
    fnp_device_type_t type;
    bool promiscuous;
    u16 nb_rx_desc;
    u16 nb_tx_desc;
    struct rte_ether_addr mac;
    const fnp_device_ops_t* ops;
};

struct fnp_ifaddr
{
    u16 id;
    fnp_device_t* dev;
    char* ip; // 点分十进制IPv4字符串，便于日志打印
    u32 local_ip_be;
    u32 netmask_be;
    u32 network_be;
    u8 prefix_len;
};

typedef struct fnp_network
{
    int device_count;
    fnp_device_t devices[FNP_MAX_DEVICE_NUM];
    int ifaddr_count;
    fnp_ifaddr_t ifaddrs[FNP_MAX_IFADDR_NUM];
    struct rte_hash* ifaddr_tbl;
} fnp_network_t;

int init_fnp_device_layer(fnp_config* conf);

int init_fnp_ifaddr_layer(fnp_config* conf);

int get_fnp_device_count(void);

fnp_device_t* get_fnp_device(int index);

fnp_device_t* lookup_device_by_id(u16 device_id);

fnp_device_t* lookup_device_by_name(const char* name);

fnp_device_t* lookup_device_by_port(u16 port_id);

const struct rte_ether_addr* get_device_mac(const fnp_device_t* dev);

int get_fnp_ifaddr_count(void);

fnp_ifaddr_t* get_fnp_ifaddr(int index);

fnp_ifaddr_t* lookup_ifaddr(u32 local_ip_be);

fnp_ifaddr_t* lookup_ifaddr_by_id(u16 ifaddr_id);

fnp_ifaddr_t* find_ifaddr_on_device(fnp_device_t* dev, u32 local_ip_be);

fnp_ifaddr_t* find_ifaddr_on_device_for_remote(fnp_device_t* dev, u32 remote_ip_be);

fnp_ifaddr_t* add_dynamic_ifaddr(fnp_device_t* dev, u32 local_ip_be);

static inline bool is_local_ipaddr(u32 ip)
{
    return lookup_ifaddr(ip) != NULL;
}

#endif // FNP_NETWORK_H
