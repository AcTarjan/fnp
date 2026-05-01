#include "ether.h"
#include "fnp_context.h"
#include "fnp_worker.h"
#include "fnp_ring.h"
#include "arp.h"

#include <rte_ethdev.h>
#include <stdlib.h>
#include <string.h>

#define ETHER_INPUT_TABLE_SIZE 65536

static ether_input_func ether_input_table[ETHER_INPUT_TABLE_SIZE];

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

static int configure_rss_reta(uint16_t port, uint16_t nb_queues, const struct rte_eth_dev_info *dev_info)
{
    if (nb_queues <= 1 || dev_info == NULL || dev_info->reta_size == 0)
    {
        return FNP_OK;
    }

    uint16_t reta_size = dev_info->reta_size;
    uint16_t reta_group_count = (uint16_t)((reta_size + RTE_ETH_RETA_GROUP_SIZE - 1) / RTE_ETH_RETA_GROUP_SIZE);
    struct rte_eth_rss_reta_entry64 *reta_conf = calloc(reta_group_count, sizeof(*reta_conf));
    if (reta_conf == NULL)
    {
        return FNP_ERR_MBUF_ALLOC;
    }

    for (uint16_t i = 0; i < reta_size; ++i)
    {
        uint16_t group = (uint16_t)(i / RTE_ETH_RETA_GROUP_SIZE);
        uint16_t offset = (uint16_t)(i % RTE_ETH_RETA_GROUP_SIZE);
        reta_conf[group].mask |= (uint64_t)1 << offset;
        reta_conf[group].reta[offset] = (uint16_t)(i % nb_queues);
    }

    int ret = rte_eth_dev_rss_reta_update(port, reta_conf, reta_size);
    free(reta_conf);
    if (ret != 0)
    {
        printf("port%u failed to configure RSS RETA size=%u queues=%u: %s\n",
               port, reta_size, nb_queues, strerror(-ret));
        return ret;
    }

    printf("port%u configured RSS RETA size=%u across %u queues\n", port, reta_size, nb_queues);
    return FNP_OK;
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

static void ether_drop_input(struct rte_mbuf *m)
{
    free_mbuf(m);
}

int init_ether_layer(void)
{
    for (u32 i = 0; i < ETHER_INPUT_TABLE_SIZE; ++i)
    {
        ether_input_table[i] = ether_drop_input;
    }

    return FNP_OK;
}

int ether_register_input(u16 ethertype, ether_input_func input)
{
    ether_input_table[ethertype] = input == NULL ? ether_drop_input : input;
    return FNP_OK;
}

void ether_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ether_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);

    u16 type = rte_be_to_cpu_16(hdr->ether_type);
    ether_input_table[type](m);
}

bool ether_send_mbuf(struct rte_mbuf *m, fnp_device_t *dev, struct rte_ether_addr *dmac, u16 type)
{
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, RTE_ETHER_HDR_LEN);
    if (unlikely(hdr == NULL))
    {
        free_mbuf(m);
        return false;
    }

    rte_ether_addr_copy(&dev->mac, &hdr->src_addr);
    rte_ether_addr_copy(dmac, &hdr->dst_addr);
    hdr->ether_type = fnp_swap16(type);
    m->l2_len = RTE_ETHER_HDR_LEN;

    fnp_worker_t *worker = get_local_worker();
    fnp_ring_t *tx_ring = get_device_tx_ring(dev, worker->queue_id);
    if (unlikely(fnp_ring_enqueue(tx_ring, m) == 0))
    {
        free_mbuf(m);
        return false;
    }

    return true;
}

bool ether_device_send(fnp_device_t *dev, struct rte_mbuf *m, const struct rte_ether_addr *dmac)
{
    return ether_send_mbuf(m, dev, (struct rte_ether_addr *)dmac, RTE_ETHER_TYPE_IPV4);
}

static u16 ether_device_recv(fnp_device_t *dev, u16 queue_id)
{
#define MBUF_BURST_SIZE 256
    struct rte_mbuf *mbufs[MBUF_BURST_SIZE] = {0};
    u16 rx_num = rte_eth_rx_burst(dev->port_id, queue_id, mbufs, MBUF_BURST_SIZE);
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

static int ether_device_init(fnp_device_t *dev, const fnp_device_config *conf, int nb_queues)
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
    const uint64_t requested_rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_UDP;
    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode = nb_queues > 1 ? RTE_ETH_MQ_RX_RSS : RTE_ETH_MQ_RX_NONE,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_hf = nb_queues > 1 ? requested_rss_hf : 0,
            },
        },
        .txmode = {
            .offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM | RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
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
    if (nb_queues > 1)
    {
        uint64_t rss_hf = requested_rss_hf & dev_info.flow_type_rss_offloads;
        if (rss_hf == 0)
        {
            port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
            port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
            printf("port%d does not advertise IPv4+UDP RSS, fallback to queue0-compatible receive path\n", port);
        }
        else
        {
            port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
            printf("port%d enable RSS hf=%#llx for IPv4+UDP receive steering\n",
                   port, (unsigned long long)rss_hf);
        }
    }

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

    ret = configure_rss_reta(port, (uint16_t)nb_queues, &dev_info);
    if (ret != FNP_OK)
    {
        rte_eth_dev_stop(port);
        return ret;
    }

    if (dev->promiscuous)
    {
        ret = rte_eth_promiscuous_enable(port);
        printf("set port to promiscuous mode: %d\n", ret);
    }

    return FNP_OK;
}

static const fnp_device_ops_t ether_device_ops = {
    .init = ether_device_init,
    .recv = ether_device_recv,
    .send = ether_device_send,
};

int init_ether_device_layer(fnp_config *conf)
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

    fnp_device_context_t *device_context = &get_fnp_context()->device;
    memset(device_context, 0, sizeof(*device_context));
    device_context->count = device_count;
    u16 next_dpdk_port_id = 0;
    for (int i = 0; i < device_count; ++i)
    {
        const fnp_device_config *device_conf = &conf->network.devices[i];
        fnp_device_t *dev = &device_context->devices[i];
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

        if (dev->type != fnp_device_type_ethernet)
        {
            printf("device type %s is not implemented yet: %s\n",
                   device_conf->device_type == NULL ? "" : device_conf->device_type,
                   dev->name);
            return FNP_ERR_PARAM;
        }

        dev->port_id = next_dpdk_port_id++;
        dev->ops = &ether_device_ops;

        for (int q = 0; q < conf->worker.lcores_count; ++q)
        {
            dev->tx_rings[q] = fnp_ring_create(conf->worker.worker_tx_ring_size, false, false);
            if (dev->tx_rings[q] == NULL)
            {
                printf("create device tx ring failed: device=%s queue=%d size=%d\n",
                       dev->name, q, conf->worker.worker_tx_ring_size);
                return FNP_ERR_CREATE_RING;
            }
        }

        int ret = dev->ops->init(dev, device_conf, conf->worker.lcores_count);
        CHECK_RET(ret);
    }

    return FNP_OK;
}
