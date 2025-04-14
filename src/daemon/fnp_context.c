#include "fnp_context.h"

#include "fnp_error.h"
#include "fnp_msg.h"

#include "fnp_frontend.h"
#include "arp.h"
#include "ipv4.h"
#include "tcp.h"
#include "fnp_socket.h"

#include <rte_ethdev.h>
#include <rte_pdump.h>

fnp_context fnp;

struct rte_mbuf *alloc_mbuf()
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(fnp.pool5);
    if (unlikely(m == NULL))
    {
        printf("alloc mbuf failed, start to wait\n");
        i32 avail;
        while (1)
        {
            avail = rte_mempool_avail_count(fnp.pool5);
            if (avail > 0)
                break;
            rte_delay_us_block(10);
        }
        m = rte_pktmbuf_alloc(fnp.pool5);
        printf("alloc a mbuf from pool5: %p, %d\n", m, avail);
    }
    return m;
}

i32 iface_init(fnp_context *ctx)
{
    fnp_config *conf = &ctx->conf;
    u16 avail_ports = rte_eth_dev_count_avail();
    if (avail_ports < conf->ports_count)
    {
        printf("dpdk has %u avail ports found\n", avail_ports);
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    u32 socket_id = rte_socket_id();

    ctx->iface_num = conf->ports_count;
    for (u16 id = 0; id < conf->ports_count; id++)
    {
        fnp_iface_t *iface = &ctx->ifaces[id];
        port_config *pconf = &conf->ports[id];

        int ret = rte_eth_dev_info_get(id, &dev_info);
        if (ret != 0)
        {
            printf("fail to get device(port %u) info: %s\n", id, strerror(-ret));
            return -1;
        }
        printf("max_mtu: %u\n", dev_info.max_mtu);
        printf("min_mtu: %u\n", dev_info.min_mtu);
        printf("max_tx_queues: %u\n", dev_info.max_tx_queues);
        printf("max_rx_queues: %u\n", dev_info.max_rx_queues);

        iface->id = id;
        iface->ip = ipv4_ston(pconf->ip);
        iface->mask = ipv4_ston(pconf->ip_mask);
        iface->gateway = ipv4_ston(pconf->gateway);

        iface->tx_queue = fnp_pring_alloc(pconf->tx_ring_size);
        if (iface->tx_queue == NULL)
        {
            printf("create tx_queue error!\n");
            return -1;
        }

        rte_eth_macaddr_get(id, &iface->mac);
        printf("local mac is " RTE_ETHER_ADDR_PRT_FMT "\n", RTE_ETHER_ADDR_BYTES(&iface->mac));

        struct rte_eth_conf eth_conf = {};
        ret = rte_eth_dev_configure(id, pconf->nb_rx_queue, pconf->nb_tx_queue, &eth_conf);
        if (ret != 0)
        {
            printf("fail to rte_eth_dev_configure: %s\n", strerror(-ret));
            return -1;
        }

        struct rte_eth_txconf txq_conf;
        txq_conf = dev_info.default_txconf;
        // txq_conf.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
        ret = rte_eth_tx_queue_setup(id, 0, pconf->nb_tx_desc, socket_id, &txq_conf);
        if (ret < 0)
        {
            printf("fail to rte_eth_tx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        fnp.rx_pool = rte_pktmbuf_pool_create("RxMbufPool", pconf->rx_mbuf_pool_size, 0,
                                              0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (fnp.rx_pool == NULL)
        {
            printf("create rx_pool error!\n");
            return -1;
        }

        struct rte_eth_rxconf rxq_conf;
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = eth_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(id, 0, pconf->nb_rx_desc, socket_id, &rxq_conf, fnp.rx_pool);
        if (ret < 0)
        {
            printf("fail to rte_eth_rx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        ret = rte_eth_dev_start(id);
        if (ret != 0)
        {
            printf("fail to start port: %s\n", strerror(-ret));
            return -1;
        }

        /* Enable RX in promiscuous mode for the Ethernet device. */
        if (pconf->promiscuous)
        {
            ret = rte_eth_promiscuous_enable(id);
            printf("set port to promiscuous mode: %d\n", ret);
        }
    }

    return 0;
}

i32 init_dpdk(fnp_context *ctx)
{
    dpdk_config *dconf = &ctx->conf.dpdk;
    i32 ret = rte_eal_init(dconf->argc, dconf->argv);
    if (ret < 0)
    {
        printf("rte_eal_init error!\n");
        return -1;
    }

    // 初始化pdump, 用于dpdk-pdump和dpdk-dumpcap抓包
    ret = rte_pdump_init();
    if (ret < 0)
    {
        printf("rte_pdump_init error!\n");
        return -1;
    }

    /* init RTE timer library */
    rte_timer_subsystem_init();

    u32 socket_id = rte_socket_id();
    ctx->pool2 = rte_pktmbuf_pool_create(FNP_MBUF_MEMPOOL_NAME, dconf->mbuf_pool_size, 0,
                                         0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (ctx->pool2 == NULL)
    {
        printf("create gDirectPool failed!\n");
        return -1;
    }

    ctx->pool5 = rte_pktmbuf_pool_create("fnp_mbuf_pool5", dconf->mbuf_pool_size, 0,
                                         0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (ctx->pool5 == NULL)
    {
        printf("create gDirectPool failed!\n");
        return -1;
    }
    ctx->clone_pool = rte_pktmbuf_pool_create("fnp_clone_pool", dconf->mbuf_pool_size, 0,
                                              0, 0, socket_id);
    if (ctx->clone_pool == NULL)
    {
        printf("create clone pool failed!\n");
        return -1;
    }

    return iface_init(ctx);
}

i32 init_fnp_daemon(char *path)
{

    fnp_config *conf = &fnp.conf;
    i32 ret = parse_fnp_config(path, conf);
    if (ret != 0)
    {
        FNP_ERR("parse config error!\n");
        return -1;
    }

    ret = init_dpdk(&fnp);
    CHECK_RET(ret);

    ret = init_arp_layer();
    CHECK_RET(ret);

    init_ipv4_layer();

    init_tcp_layer();

    // 初始化sock层
    ret = init_socket_layer();
    CHECK_RET(ret);

    ret = init_frontend_layer();
    CHECK_RET(ret);

    // 初始化msg
    ret = init_msg_layer();
    CHECK_RET(ret);

    return 0;
}