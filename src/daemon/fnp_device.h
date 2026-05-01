#ifndef FNP_DEVICE_H
#define FNP_DEVICE_H

#include "fnp_common.h"
#include "fnp.h"
#include "fnp_ring.h"
#include "libfnp-conf.h"

#include <rte_ether.h>
#include <rte_mbuf.h>

#define FNP_MAX_DEVICE_NUM FNP_DEVICE_MAX

typedef enum fnp_device_type
{
    fnp_device_type_ethernet = 1,
    fnp_device_type_tap,
    fnp_device_type_tun,
} fnp_device_type_t;

typedef enum fnp_device_driver
{
    fnp_device_driver_none = 0,
    fnp_device_driver_physical,
    fnp_device_driver_dpdk_tap,
} fnp_device_driver_t;

typedef struct fnp_device fnp_device_t;

typedef int (*fnp_device_init_func)(fnp_device_t *dev, const fnp_device_config *conf, int nb_queues);
typedef u16 (*fnp_device_recv_func)(fnp_device_t *dev, u16 queue_id);
typedef bool (*fnp_device_send_func)(fnp_device_t *dev, struct rte_mbuf *m, const struct rte_ether_addr *dmac);

typedef struct fnp_device_ops
{
    fnp_device_init_func init;
    fnp_device_recv_func recv;
    fnp_device_send_func send;
} fnp_device_ops_t;

struct fnp_device
{
    u16 id;
    u16 port_id;
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

typedef struct fnp_device_context
{
    int count;
    fnp_device_t devices[FNP_MAX_DEVICE_NUM];
} fnp_device_context_t;

fnp_device_type_t parse_device_type(const char *type);

fnp_device_driver_t parse_device_driver(const char *driver);

bool validate_device_type_driver(fnp_device_type_t type, fnp_device_driver_t driver);

int get_fnp_device_count(void);

fnp_device_t *get_fnp_device(int index);

fnp_device_t *lookup_device_by_id(u16 device_id);

fnp_device_t *lookup_device_by_name(const char *name);

fnp_device_t *lookup_device_by_port(u16 port_id);

const struct rte_ether_addr *get_device_mac(const fnp_device_t *dev);

static inline fnp_ring_t *get_device_tx_ring(const fnp_device_t *dev, u16 queue_id)
{
    return dev->tx_rings[queue_id];
}

static inline bool is_ethernet_device(const fnp_device_t *dev)
{
    return dev->type == fnp_device_type_ethernet;
}

static inline bool is_dpdk_tap_driver(const fnp_device_t *dev)
{
    return dev->driver == fnp_device_driver_dpdk_tap;
}

static inline bool is_tun_device(const fnp_device_t *dev)
{
    return dev->type == fnp_device_type_tun;
}

static inline bool is_tap_device(const fnp_device_t *dev)
{
    return dev->type == fnp_device_type_tap;
}

#endif // FNP_DEVICE_H
