#include "fnp_iface.h"
#include "fnp_sockaddr.h"
#include "fnp_worker.h"
#include "flow_table.h"
#include "hash.h"

#include <rte_ethdev.h>

// Mellanox Linux's driver key
static uint8_t default_rsskey_40bytes[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

static uint8_t default_rsskey_52bytes[52] = {
    0x44, 0x39, 0x79, 0x6b, 0xb5, 0x4c, 0x50, 0x23,
    0xb6, 0x75, 0xea, 0x5b, 0x12, 0x4f, 0x9f, 0x30,
    0xb8, 0xa2, 0xc0, 0x3d, 0xdf, 0xdc, 0x4d, 0x02,
    0xa0, 0x8c, 0x9b, 0x33, 0x4a, 0xf6, 0x4a, 0x4c,
    0x05, 0xc6, 0xfa, 0x34, 0x39, 0x58, 0xd8, 0x55,
    0x7d, 0x99, 0x58, 0x3a, 0xe1, 0x38, 0xc9, 0x2e,
    0x81, 0x15, 0x03, 0x66
};

static uint8_t symmetric_rsskey[52] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a
};

static int rsskey_len = sizeof(default_rsskey_40bytes);
static uint8_t* rsskey = default_rsskey_40bytes;

static uint16_t rss_reta_size[RTE_MAX_ETHPORTS];

static int fnp_iface_count = 0;
static fnp_iface_t ifaces[MAX_IFACE_NUM];

static int port_count = 0;
static struct rte_ether_addr ports_mac[MAX_PORT_NUM];

struct rte_ether_addr* get_port_mac(int id)
{
    return &ports_mac[id];
}

// 目前是遍历, 后续可以iface数量较多的时候可以考虑使用hash表
fnp_iface_t* lookup_iface(u32 ip)
{
    for (i32 i = 0; i < fnp_iface_count; ++i)
    {
        if (ifaces[i].ip == ip)
        {
            return &ifaces[i];
        }
    }

    return NULL;
}

fnp_iface_t* find_iface_for_outlet(u32 rip)
{
    for (i32 i = 0; i < fnp_iface_count; ++i)
    {
        fnp_iface_t* iface = &ifaces[i];
        if ((iface->ip & iface->mask) == (rip & iface->mask))
        {
            return &ifaces[i];
        }
    }

    return &ifaces[0];
}

u32 find_next_hop(fnp_iface_t* iface, u32 rip)
{
    if ((iface->ip & iface->mask) != (rip & iface->mask))
    {
        return iface->gateway;
    }

    return rip;
}

static i32 init_fnp_iface(int port, port_config* conf, int nb_queues)
{
    for (int i = 0; i < conf->networks_count; i++)
    {
        network_config* network = &conf->networks[i];
        fnp_iface_t* iface = &ifaces[fnp_iface_count];
        iface->id = fnp_iface_count++;
        iface->port = port;
        iface->name = fnp_string_duplicate(network->name);
        iface->ip = fnp_ipv4_ston(network->ip);
        iface->mask = fnp_ipv4_ston(network->ip_mask);
        iface->gateway = fnp_ipv4_ston(network->gateway);
    }

    rte_eth_macaddr_get(port, &ports_mac[port]); //填充mac地址
    printf("port %d mac is " RTE_ETHER_ADDR_PRT_FMT "\n", port, RTE_ETHER_ADDR_BYTES(&ports_mac[port]));

    // 获取网卡设备信息
    u32 socket_id = rte_eth_dev_socket_id(port);
    struct rte_eth_conf port_conf = {
        .txmode = {
            .offloads =
            // RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
            RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
            RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
            RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
            // RTE_ETH_TX_OFFLOAD_SCTP_CKSUM |
            // RTE_ETH_TX_OFFLOAD_TCP_TSO |
            RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
        },
        // 暂不配置rxmode
    };

    struct rte_eth_dev_info dev_info;
    int ret = rte_eth_dev_info_get(port, &dev_info);
    if (ret != 0)
    {
        printf("fail to get device(port %u) info: %s\n", port, strerror(-ret));
        return -1;
    }

    printf("port%d max_mtu: %u\n", port, dev_info.max_mtu);
    printf("port%d min_mtu: %u\n", port, dev_info.min_mtu);
    printf("port%d max_tx_queues: %u\n", port, dev_info.max_tx_queues);
    printf("port%d max_rx_queues: %u\n", port, dev_info.max_rx_queues);
    if (nb_queues > dev_info.max_rx_queues)
    {
        rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than max_rx_queues[%d]\n",
                 nb_queues, dev_info.max_rx_queues);
    }

    if (nb_queues > dev_info.max_tx_queues)
    {
        rte_exit(EXIT_FAILURE, "num_procs[%d] bigger than max_tx_queues[%d]\n",
                 nb_queues, dev_info.max_tx_queues);
    }

    // 设置网卡设备的txmode
    port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    if ((dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) == 0)
    {
        printf("Unsupported RTE_ETH_TX_OFFLOAD_IPV4_CKSUM\n");
    }
    if ((dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM) == 0)
    {
        printf("Unsupported RTE_ETH_TX_OFFLOAD_UDP_CKSUM\n");
    }
    if ((dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM) == 0)
    {
        printf("Unsupported RTE_ETH_TX_OFFLOAD_TCP_CKSUM\n");
    }

    /* Set RSS mode */
    if (0)
    {
        uint64_t default_rss_hf = RTE_ETH_RSS_PROTO_MASK;
        port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        port_conf.rx_adv_conf.rss_conf.rss_hf = default_rss_hf;
        if (dev_info.hash_key_size == 52)
        {
            rsskey = default_rsskey_52bytes;
            rsskey_len = 52;
        }

        if (0)
        {
            printf("Use symmetric Receive-side Scaling(RSS) key\n");
            rsskey = symmetric_rsskey;
        }

        port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
        port_conf.rx_adv_conf.rss_conf.rss_key_len = rsskey_len;
        port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads; //该字段为0
        if (port_conf.rx_adv_conf.rss_conf.rss_hf != RTE_ETH_RSS_PROTO_MASK)
        {
            printf("Port %u modified RSS hash function based on hardware support,"
                   "requested:%#"PRIx64" configured:%#"PRIx64"\n",
                   port, default_rss_hf, port_conf.rx_adv_conf.rss_conf.rss_hf);
        }

        if (dev_info.reta_size)
        {
            /* reta size must be power of 2 */
            assert((dev_info.reta_size & (dev_info.reta_size - 1)) == 0);

            rss_reta_size[port] = dev_info.reta_size;
            printf("port[%d]: rss table size: %d\n", port, dev_info.reta_size);
        }
    }

    // 配置网卡的rxmode
    if (0)
    {
        /* 剥离以太网帧尾部的CRC字段 */
        port_conf.rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_KEEP_CRC;

        /* Set Rx checksum checking */
        if ((dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM) &&
            (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM) &&
            (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM))
        {
            printf("RX checksum offload supported\n");
            port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_CHECKSUM;
        }
    }

    ret = rte_eth_dev_configure(port, nb_queues, nb_queues, &port_conf);
    if (ret != 0)
    {
        printf("fail to rte_eth_dev_configure: %s\n", strerror(-ret));
        return -1;
    }

    uint16_t nb_rxd = conf->nb_rx_desc;
    uint16_t nb_txd = conf->nb_tx_desc;
    // 根据硬件能力调整接收和发送描述符的数量
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (ret < 0)
        printf("Could not adjust number of descriptors for port%d: %d\n", port, ret);

    // 配置接收队列和发送队列
    struct rte_eth_txconf txq_conf = {0};
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.txmode.offloads;

    struct rte_eth_rxconf rxq_conf = {0};
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    for (int i = 0; i < nb_queues; i++)
    {
        ret = rte_eth_tx_queue_setup(port, i, nb_txd, socket_id, &txq_conf);
        if (ret < 0)
        {
            printf("fail to rte_eth_tx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        fnp_worker_t* worker = get_fnp_worker(i);
        ret = rte_eth_rx_queue_setup(port, i, nb_rxd, socket_id, &rxq_conf, worker->rx_pool);
        if (ret < 0)
        {
            printf("fail to rte_eth_rx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }
    }

    ret = rte_eth_dev_start(port);
    if (ret != 0)
    {
        printf("fail to start port: %s\n", strerror(-ret));
        return -1;
    }

    /* Enable RX in promiscuous mode for the Ethernet device. */
    if (conf->promiscuous)
    {
        ret = rte_eth_promiscuous_enable(port);
        printf("set port to promiscuous mode: %d\n", ret);
    }

    // 对于多个worker需要配置流表
    if (nb_queues > 1)
    {
        ret = init_flow_table(port);
        CHECK_RET(ret);
    }
    else
    {
        printf("fnp-worker number is %d, don't init flow table\n", nb_queues);
    }

    return FNP_OK;
}


i32 init_fnp_iface_layer(fnp_config* conf)
{
    u16 avail_ports = rte_eth_dev_count_avail();
    if (avail_ports < conf->ports_count)
    {
        printf("dpdk has %u avail ports found\n", avail_ports);
        return -1;
    }


    port_count = conf->ports_count;
    for (i32 id = 0; id < conf->ports_count; id++)
    {
        int ret = init_fnp_iface(id, &conf->ports[id], conf->worker.lcores_count);
        CHECK_RET(ret);
    }

    return FNP_OK;
}
