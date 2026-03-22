#include "fnp_network.h"

#include "fnp_context.h"
#include "ether.h"
#include "tap.h"
#include "tun.h"
#include "fnp_error.h"
#include "fnp_worker.h"
#include "flow_table.h"
#include "hash.h"

#include <rte_ethdev.h>
#include <string.h>

#define IFADDR_TABLE_SIZE 256

#define network_context (get_fnp_context()->net)

#define MBUF_BURST_SIZE 64
#define DEVICE_TX_BURST_SIZE 128

static bool is_tap_driver_name(const char *driver_name)
{
    return driver_name != NULL && strstr(driver_name, "net_tap") != NULL;
}

static int resolve_port_socket_id(uint16_t port)
{
    int socket_id = rte_eth_dev_socket_id(port);
    if (socket_id == SOCKET_ID_ANY || socket_id < 0)
    {
        socket_id = rte_socket_id();
    }

    return socket_id < 0 ? 0 : socket_id;
}

static u8 ipv4_mask_prefix_len(u32 mask_be)
{
    u32 mask = rte_be_to_cpu_32(mask_be);
    u8 prefix_len = 0;
    while ((mask & 0x80000000u) != 0)
    {
        ++prefix_len;
        mask <<= 1;
    }

    return prefix_len;
}

static bool parse_mac_addr(const char *text, struct rte_ether_addr *mac)
{
    unsigned int bytes[RTE_ETHER_ADDR_LEN];
    if (text == NULL || mac == NULL)
    {
        return false;
    }

    if (sscanf(text, "%x:%x:%x:%x:%x:%x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != RTE_ETHER_ADDR_LEN)
    {
        return false;
    }

    for (int i = 0; i < RTE_ETHER_ADDR_LEN; ++i)
    {
        mac->addr_bytes[i] = (uint8_t)bytes[i];
    }

    return true;
}

static void init_virtual_tap_mac(fnp_device_t *dev, const fnp_device_config *conf)
{
    if (dev == NULL)
    {
        return;
    }

    memset(&dev->mac, 0, sizeof(dev->mac));
    if (conf != NULL && conf->mac != NULL && conf->mac[0] != '\0')
    {
        if (parse_mac_addr(conf->mac, &dev->mac))
        {
            return;
        }

        printf("invalid mac address on tap device %s: %s\n", dev->name, conf->mac);
    }

    dev->mac.addr_bytes[0] = 0x02;
    dev->mac.addr_bytes[1] = 0x00;
    dev->mac.addr_bytes[2] = 0x00;
    dev->mac.addr_bytes[3] = 0x00;
    dev->mac.addr_bytes[4] = (u8)((dev->id >> 8) & 0xff);
    dev->mac.addr_bytes[5] = (u8)(dev->id & 0xff);
}

static fnp_device_type_t parse_device_type(const char *type)
{
    if (type == NULL || type[0] == '\0' || strcmp(type, "ethernet") == 0)
    {
        return fnp_device_type_ethernet;
    }

    if (strcmp(type, "tap") == 0)
    {
        return fnp_device_type_tap;
    }

    if (strcmp(type, "tun") == 0)
    {
        return fnp_device_type_tun;
    }

    return 0;
}

static fnp_device_driver_t parse_device_driver(const char *driver)
{
    if (driver == NULL || driver[0] == '\0')
    {
        return fnp_device_driver_none;
    }

    if (strcmp(driver, "physical") == 0)
    {
        return fnp_device_driver_physical;
    }

    if (strcmp(driver, "dpdk_tap") == 0)
    {
        return fnp_device_driver_dpdk_tap;
    }

    return 0;
}

static bool validate_device_type_driver(fnp_device_type_t type, fnp_device_driver_t driver)
{
    switch (type)
    {
    case fnp_device_type_ethernet:
        return driver == fnp_device_driver_physical || driver == fnp_device_driver_dpdk_tap;
    case fnp_device_type_tap:
    case fnp_device_type_tun:
        return driver == fnp_device_driver_none;
    default:
        return false;
    }
}

static int dpdk_device_init(fnp_device_t *dev, const fnp_device_config *conf, int nb_queues)
{
    if (dev == NULL || conf == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (unlikely(!is_ethernet_device(dev)))
    {
        return FNP_ERR_PARAM;
    }

    const int port = dev->port_id;
    rte_eth_macaddr_get(port, &dev->mac);
    if (conf->mac != NULL && conf->mac[0] != '\0')
    {
        struct rte_ether_addr configured_mac;
        if (!parse_mac_addr(conf->mac, &configured_mac))
        {
            printf("invalid mac address on device %s: %s\n", conf->name, conf->mac);
            return FNP_ERR_PARAM;
        }
        rte_ether_addr_copy(&configured_mac, &dev->mac);
    }

    printf("port %d mac is " RTE_ETHER_ADDR_PRT_FMT "\n", port, RTE_ETHER_ADDR_BYTES(&dev->mac));

    int socket_id = resolve_port_socket_id(port);
    struct rte_eth_conf port_conf = {
        .txmode = {
            .offloads =
                RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
                RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
                RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
        },
    };

    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0)
    {
        printf("fail to get device(port %u) info: %s\n", port, strerror(-ret));
        return ret;
    }

    const bool is_tap_port = is_tap_driver_name(dev_info.driver_name);
    printf("port%d driver: %s\n", port, dev_info.driver_name ? dev_info.driver_name : "unknown");
    if (is_tap_port)
    {
        printf("port%d is backed by DPDK TAP PMD, suitable for local kernel interop testing\n", port);
    }

    printf("port%d max_mtu: %u\n", port, dev_info.max_mtu);
    printf("port%d min_mtu: %u\n", port, dev_info.min_mtu);
    printf("port%d max_tx_queues: %u\n", port, dev_info.max_tx_queues);
    printf("port%d max_rx_queues: %u\n", port, dev_info.max_rx_queues);

    if (nb_queues > dev_info.max_rx_queues || nb_queues > dev_info.max_tx_queues)
    {
        return FNP_ERR_PARAM;
    }

    port_conf.txmode.offloads &= dev_info.tx_offload_capa;

    ret = rte_eth_dev_configure(port, nb_queues, nb_queues, &port_conf);
    if (ret != 0)
    {
        printf("fail to rte_eth_dev_configure: %s\n", strerror(-ret));
        return ret;
    }

    uint16_t nb_rxd = dev->nb_rx_desc;
    uint16_t nb_txd = dev->nb_tx_desc;
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret < 0)
    {
        printf("Could not adjust number of descriptors for port%d: %d\n", port, ret);
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    struct rte_eth_rxconf rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    for (int i = 0; i < nb_queues; ++i)
    {
        ret = rte_eth_tx_queue_setup(port, i, nb_txd, socket_id, &txq_conf);
        if (ret < 0)
        {
            return ret;
        }

        fnp_worker_t *worker = get_fnp_worker(i);
        ret = rte_eth_rx_queue_setup(port, i, nb_rxd, socket_id, &rxq_conf, worker->rx_pool);
        if (ret < 0)
        {
            return ret;
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret != 0)
    {
        return ret;
    }

    if (dev->promiscuous)
    {
        ret = rte_eth_promiscuous_enable(port);
        printf("set port to promiscuous mode: %d\n", ret);
    }

    if (nb_queues > 1)
    {
        if (is_dpdk_tap_driver(dev))
        {
            printf("skip flow table init on TAP port %u, use a single worker queue for test mode\n", port);
        }
        else
        {
            ret = init_flow_table(port);
            CHECK_RET(ret);
        }
    }

    return FNP_OK;
}

static u16 dpdk_device_recv(fnp_device_t *dev, u16 queue_id, u16 budget)
{
    struct rte_mbuf *mbufs[MBUF_BURST_SIZE] = {0};
    u16 rx_num = rte_eth_rx_burst(dev->port_id, queue_id, mbufs, RTE_MIN(budget, (u16)MBUF_BURST_SIZE));
    for (u16 i = 0; i < rx_num; ++i)
    {
        if (likely(i + 1 < rx_num))
        {
            rte_prefetch1(rte_pktmbuf_mtod(mbufs[i + 1], void *));
        }

        rte_prefetch0(rte_pktmbuf_mtod(mbufs[i], void *));
        ether_recv_mbuf(mbufs[i]);
    }

    return rx_num;
}

u16 fnp_device_flush_tx(fnp_device_t *dev, u16 queue_id, u16 budget)
{
    fnp_ring_t *tx_ring = get_device_tx_ring(dev, queue_id);
    struct rte_mbuf *mbufs[DEVICE_TX_BURST_SIZE] = {0};

    if (unlikely(dev == NULL || !is_ethernet_device(dev) || tx_ring == NULL))
    {
        return 0;
    }

    u16 burst_size = RTE_MIN(budget, (u16)DEVICE_TX_BURST_SIZE);
    u16 tx_num = fnp_ring_dequeue_burst(tx_ring, (void **)mbufs, burst_size);
    if (unlikely(tx_num == 0))
    {
        return 0;
    }

    u16 sent = rte_eth_tx_burst(dev->port_id, queue_id, mbufs, tx_num);
    if (unlikely(sent < tx_num))
    {
        rte_pktmbuf_free_bulk(&mbufs[sent], tx_num - sent);
    }

    return tx_num;
}

static const fnp_device_ops_t dpdk_device_ops = {
    .init = dpdk_device_init,
    .recv = dpdk_device_recv,
    .send = ether_device_send,
};

static const fnp_device_ops_t virtual_tap_device_ops = {
    .send = ether_device_send,
};

static const fnp_device_ops_t virtual_tun_device_ops = {
    .send = tun_device_send,
};

int get_fnp_device_count(void)
{
    return network_context.device_count;
}

fnp_device_t *get_fnp_device(int index)
{
    if (index < 0 || index >= network_context.device_count)
    {
        return NULL;
    }

    return &network_context.devices[index];
}

fnp_device_t *lookup_device_by_id(u16 device_id)
{
    for (int i = 0; i < network_context.device_count; ++i)
    {
        if (network_context.devices[i].id == device_id)
        {
            return &network_context.devices[i];
        }
    }

    return NULL;
}

fnp_device_t *lookup_device_by_name(const char *name)
{
    if (name == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < network_context.device_count; ++i)
    {
        if (strcmp(network_context.devices[i].name, name) == 0)
        {
            return &network_context.devices[i];
        }
    }

    return NULL;
}

fnp_device_t *lookup_device_by_port(u16 port_id)
{
    for (int i = 0; i < network_context.device_count; ++i)
    {
        if (network_context.devices[i].port_id == port_id)
        {
            return &network_context.devices[i];
        }
    }

    return NULL;
}

const struct rte_ether_addr *get_device_mac(const fnp_device_t *dev)
{
    return (is_ethernet_device(dev) || is_tap_device(dev)) ? &dev->mac : NULL;
}

int get_fnp_ifaddr_count(void)
{
    return network_context.ifaddr_count;
}

fnp_ifaddr_t *get_fnp_ifaddr(int index)
{
    if (index < 0 || index >= network_context.ifaddr_count)
    {
        return NULL;
    }

    return &network_context.ifaddrs[index];
}

fnp_ifaddr_t *lookup_ifaddr(u32 local_ip_be)
{
    fnp_ifaddr_t *ifaddr = NULL;
    if (local_ip_be == 0 || network_context.ifaddr_tbl == NULL)
    {
        return NULL;
    }

    hash_lookup(network_context.ifaddr_tbl, &local_ip_be, (void **)&ifaddr);
    return ifaddr;
}

fnp_ifaddr_t *lookup_ifaddr_by_id(u16 ifaddr_id)
{
    for (int i = 0; i < network_context.ifaddr_count; ++i)
    {
        if (network_context.ifaddrs[i].id == ifaddr_id)
        {
            return &network_context.ifaddrs[i];
        }
    }

    return NULL;
}

fnp_ifaddr_t *find_ifaddr_on_device(fnp_device_t *dev, u32 local_ip_be)
{
    if (dev == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < network_context.ifaddr_count; ++i)
    {
        fnp_ifaddr_t *ifaddr = &network_context.ifaddrs[i];
        if (ifaddr->dev == dev && ifaddr->local_ip_be == local_ip_be)
        {
            return ifaddr;
        }
    }

    return NULL;
}

fnp_ifaddr_t *find_ifaddr_on_device_for_remote(fnp_device_t *dev, u32 remote_ip_be)
{
    fnp_ifaddr_t *first = NULL;
    if (dev == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < network_context.ifaddr_count; ++i)
    {
        fnp_ifaddr_t *ifaddr = &network_context.ifaddrs[i];
        if (ifaddr->dev != dev)
        {
            continue;
        }

        if (first == NULL)
        {
            first = ifaddr;
        }

        if ((remote_ip_be & ifaddr->netmask_be) == ifaddr->network_be)
        {
            return ifaddr;
        }
    }

    return first;
}

static int register_ifaddr(fnp_ifaddr_t *ifaddr)
{
    if (hash_add(network_context.ifaddr_tbl, &ifaddr->local_ip_be, ifaddr))
    {
        return FNP_OK;
    }

    return FNP_ERR_ADD_HASH;
}

fnp_ifaddr_t *add_dynamic_ifaddr(fnp_device_t *dev, u32 local_ip_be)
{
    if (dev == NULL || local_ip_be == 0)
    {
        return NULL;
    }

    fnp_ifaddr_t *existing = lookup_ifaddr(local_ip_be);
    if (existing != NULL)
    {
        return existing->dev == dev ? existing : NULL;
    }

    if (network_context.ifaddr_count >= FNP_MAX_IFADDR_NUM)
    {
        return NULL;
    }

    fnp_ifaddr_t *ifaddr = &network_context.ifaddrs[network_context.ifaddr_count];
    memset(ifaddr, 0, sizeof(*ifaddr));
    ifaddr->id = (u16)network_context.ifaddr_count;
    ifaddr->dev = dev;
    ifaddr->ip = fnp_ipv4_ntos(local_ip_be);
    ifaddr->local_ip_be = local_ip_be;
    ifaddr->netmask_be = 0xffffffffu;
    ifaddr->network_be = local_ip_be;
    ifaddr->prefix_len = 32;
    ++network_context.ifaddr_count;

    if (register_ifaddr(ifaddr) != FNP_OK)
    {
        fnp_string_free(ifaddr->ip);
        --network_context.ifaddr_count;
        return NULL;
    }

    return ifaddr;
}

int init_fnp_device_layer(fnp_config *conf)
{
    if (conf == NULL)
    {
        return FNP_ERR_PARAM;
    }

    const int device_count = conf->network.devices_count;
    int dpdk_device_count = 0;
    for (int i = 0; i < device_count; ++i)
    {
        if (parse_device_type(conf->network.devices[i].device_type) == fnp_device_type_ethernet)
        {
            ++dpdk_device_count;
        }
    }

    const u16 avail_ports = rte_eth_dev_count_avail();
    if (avail_ports < dpdk_device_count)
    {
        printf("dpdk has %u avail ports found\n", avail_ports);
        return FNP_ERR_PARAM;
    }

    memset(&network_context, 0, sizeof(network_context));
    network_context.device_count = device_count;
    u16 next_dpdk_port_id = 0;
    for (int i = 0; i < device_count; ++i)
    {
        const fnp_device_config *device_conf = &conf->network.devices[i];
        fnp_device_t *dev = &network_context.devices[i];
        fnp_device_type_t device_type = parse_device_type(device_conf->device_type);
        fnp_device_driver_t device_driver = parse_device_driver(device_conf->driver);
        if (device_type == fnp_device_type_ethernet && device_driver == fnp_device_driver_none)
        {
            device_driver = fnp_device_driver_physical;
        }

        memset(dev, 0, sizeof(*dev));
        dev->id = device_conf->id;
        dev->port_id = UINT16_MAX;
        dev->type = device_type;
        dev->driver = device_driver;
        dev->promiscuous = device_conf->promiscuous;
        dev->nb_rx_desc = (u16)device_conf->nb_rx_desc;
        dev->nb_tx_desc = (u16)device_conf->nb_tx_desc;
        snprintf(dev->name, sizeof(dev->name), "%s", device_conf->name == NULL ? "" : device_conf->name);

        if (unlikely(!validate_device_type_driver(dev->type, dev->driver)))
        {
            printf("unsupported device type/driver: name=%s type=%s driver=%s\n",
                   dev->name,
                   device_conf->device_type == NULL ? "" : device_conf->device_type,
                   device_conf->driver == NULL ? "" : device_conf->driver);
            return FNP_ERR_PARAM;
        }

        if (dev->type == fnp_device_type_tun)
        {
            dev->ops = &virtual_tun_device_ops;
            continue;
        }

        if (dev->type == fnp_device_type_tap)
        {
            init_virtual_tap_mac(dev, device_conf);
            dev->ops = &virtual_tap_device_ops;
            continue;
        }

        if (dev->type != fnp_device_type_ethernet)
        {
            printf("device type %s is not implemented yet: %s\n",
                   device_conf->device_type == NULL ? "" : device_conf->device_type,
                   dev->name);
            return FNP_ERR_PARAM;
        }

        dev->port_id = next_dpdk_port_id++;
        dev->ops = &dpdk_device_ops;

        for (int q = 0; q < conf->worker.lcores_count; ++q)
        {
            dev->tx_rings[q] = fnp_ring_create(conf->worker.tx_ring_size, false, false);
            if (dev->tx_rings[q] == NULL)
            {
                printf("create device tx ring failed: device=%s queue=%d size=%d\n",
                       dev->name, q, conf->worker.tx_ring_size);
                return FNP_ERR_CREATE_RING;
            }
        }

        int ret = dev->ops->init(dev, device_conf, conf->worker.lcores_count);
        CHECK_RET(ret);
    }

    return FNP_OK;
}

int init_fnp_ifaddr_layer(fnp_config *conf)
{
    if (conf == NULL)
    {
        return FNP_ERR_PARAM;
    }

    network_context.ifaddr_tbl = hash_create("fnp_ifaddr_tbl", IFADDR_TABLE_SIZE, sizeof(u32));
    if (network_context.ifaddr_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    network_context.ifaddr_count = 0;
    for (int i = 0; i < conf->network.devices_count; ++i)
    {
        const fnp_device_config *device_conf = &conf->network.devices[i];
        fnp_device_t *dev = lookup_device_by_id(device_conf->id);
        if (dev == NULL)
        {
            return FNP_ERR_PARAM;
        }

        for (int j = 0; j < device_conf->ifaddr_count; ++j)
        {
            if (network_context.ifaddr_count >= FNP_MAX_IFADDR_NUM)
            {
                return FNP_ERR_PARAM;
            }

            const fnp_ifaddr_config *ifaddr_conf = &device_conf->ifaddrs[j];
            fnp_ifaddr_t *ifaddr = &network_context.ifaddrs[network_context.ifaddr_count];
            memset(ifaddr, 0, sizeof(*ifaddr));
            ifaddr->id = (u16)network_context.ifaddr_count;
            ifaddr->dev = dev;
            ifaddr->ip = ifaddr_conf->ip;
            ifaddr->local_ip_be = ifaddr_conf->ip_be;
            ifaddr->netmask_be = ifaddr_conf->ip_mask_be;
            ifaddr->network_be = ifaddr_conf->ip_be & ifaddr_conf->ip_mask_be;
            ifaddr->prefix_len = ipv4_mask_prefix_len(ifaddr_conf->ip_mask_be);
            ++network_context.ifaddr_count;

            int ret = register_ifaddr(ifaddr);
            CHECK_RET(ret);

            printf("register ifaddr on %s: %s/%u\n",
                   dev->name,
                   ifaddr->ip,
                   ifaddr->prefix_len);
        }
    }

    return FNP_OK;
}
