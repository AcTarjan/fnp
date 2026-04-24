#ifndef FNP_NETWORK_H
#define FNP_NETWORK_H

#include "fnp_common.h"
#include "fnp.h"
#include "fnp_ring.h"
#include "libfnp-conf.h"

#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_mbuf.h>

#define FNP_MAX_DEVICE_NUM FNP_DEVICE_MAX
#define FNP_MAX_NETWORK_NUM FNP_NETWORK_MAX
#define FNP_MAX_IFADDR_NUM (FNP_NETWORK_MAX * FNP_INIT_IFADDR_MAX)

typedef enum fnp_device_type
{
    fnp_device_type_ethernet = 1, // 以太网设备，收发二层帧
    fnp_device_type_tap,          // 用户态二层虚拟设备，直接收发以太网帧
    fnp_device_type_tun,          // 用户态三层虚拟设备，直接收发 IPv4 包
} fnp_device_type_t;

typedef enum fnp_device_driver
{
    fnp_device_driver_none = 0, // tap/tun 等非 DPDK 后端设备使用
    fnp_device_driver_physical, // DPDK 物理网卡
    fnp_device_driver_dpdk_tap, // DPDK TAP vdev，作为 ethernet 的一种后端驱动
} fnp_device_driver_t;

typedef struct fnp_device fnp_device_t;
typedef struct fnp_ifaddr fnp_ifaddr_t;
typedef struct fnp_network_pool fnp_network_pool_t;

#define FNP_DEVICE_IFADDR_MAX 16

typedef int (*fnp_device_init_func)(fnp_device_t *dev, const fnp_device_config *conf, int nb_queues);
typedef u16 (*fnp_device_recv_func)(fnp_device_t *dev, u16 queue_id, u16 budget);
typedef void (*fnp_device_send_func)(fnp_device_t *dev,
                                     struct rte_mbuf *m,
                                     const struct rte_ether_addr *dmac);

typedef struct fnp_device_ops
{
    fnp_device_init_func init; // 设备初始化，仅底层承载设备使用
    fnp_device_recv_func recv; // worker 轮询接收入口
    fnp_device_send_func send; // 协议栈输出完整 IPv4 包到指定 device，ethernet/tap 在这里做二层封装，tun 直接递交 IP 包
} fnp_device_ops_t;

struct fnp_device
{
    u16 id;
    u16 port_id; // 仅对 ethernet 设备有效，表示 DPDK 分配的 port 编号，从0开始
    char name[32];
    fnp_device_type_t type;
    fnp_device_driver_t driver;
    bool promiscuous;
    u16 nb_rx_desc;
    u16 nb_tx_desc;
    struct rte_ether_addr mac;
    fnp_ring_t *tx_rings[FNP_MAX_WORKER_NUM];
    const fnp_device_ops_t *ops;
};

struct fnp_network_pool
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
    u16 network_id;
    fnp_device_t *dev;
    char *name;
    char *ip; // 点分十进制IPv4字符串，便于日志打印
    char network_name[FNP_NETWORK_NAME_LEN];
    u32 local_ip_be;
    u32 netmask_be;
    u32 network_be;
    u32 gateway_be;
    u8 prefix_len;
};

typedef struct fnp_network
{
    int device_count;
    fnp_device_t devices[FNP_MAX_DEVICE_NUM];
    int network_count;
    fnp_network_pool_t networks[FNP_MAX_NETWORK_NUM];
    int ifaddr_count;
    fnp_ifaddr_t ifaddrs[FNP_MAX_IFADDR_NUM];
    struct rte_hash *ifaddr_tbl;
} fnp_network_t;

int init_fnp_device_layer(fnp_config *conf);

int init_fnp_ifaddr_layer(fnp_config *conf);

int get_fnp_device_count(void);

fnp_device_t *get_fnp_device(int index);

int get_fnp_network_count(void);

fnp_network_pool_t *get_fnp_network(int index);

fnp_device_t *lookup_device_by_id(u16 device_id);

fnp_device_t *lookup_device_by_name(const char *name);

fnp_network_pool_t *lookup_network_by_name(const char *name);

fnp_device_t *lookup_device_by_port(u16 port_id);

const struct rte_ether_addr *get_device_mac(const fnp_device_t *dev);

int get_fnp_ifaddr_count(void);

fnp_ifaddr_t *get_fnp_ifaddr(int index);

fnp_ifaddr_t *lookup_ifaddr(u32 local_ip_be);

fnp_ifaddr_t *lookup_ifaddr_by_id(u16 ifaddr_id);

fnp_ifaddr_t *find_ifaddr_on_device(fnp_device_t *dev, u32 local_ip_be);

fnp_ifaddr_t *find_ifaddr_on_device_for_remote(fnp_device_t *dev, u32 remote_ip_be);

int export_network_ifaddrs(fnp_ifaddr_info_t *infos,
                           u16 info_capacity,
                           u16 *info_count);

// worker 发送阶段真正把 ethernet 设备 tx ring 里的完整二层帧刷到 DPDK 网卡。
u16 fnp_device_flush_tx(fnp_device_t *dev, u16 queue_id, u16 budget);

static inline fnp_ring_t *get_device_tx_ring(const fnp_device_t *dev, u16 queue_id)
{
    if (dev == NULL || queue_id >= FNP_MAX_WORKER_NUM)
    {
        return NULL;
    }

    return dev->tx_rings[queue_id];
}

static inline bool is_ethernet_device(const fnp_device_t *dev)
{
    return dev != NULL && dev->type == fnp_device_type_ethernet;
}

static inline bool is_dpdk_tap_driver(const fnp_device_t *dev)
{
    return dev != NULL && dev->driver == fnp_device_driver_dpdk_tap;
}

static inline bool is_tun_device(const fnp_device_t *dev)
{
    return dev != NULL && dev->type == fnp_device_type_tun;
}

static inline bool is_tap_device(const fnp_device_t *dev)
{
    return dev != NULL && dev->type == fnp_device_type_tap;
}

static inline bool is_local_ipaddr(u32 ip)
{
    return lookup_ifaddr(ip) != NULL;
}

#endif // FNP_NETWORK_H
