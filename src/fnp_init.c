#include "fnp_init.h"
#include "worker.h"

#include <rte_ethdev.h>

fnp_context fnp;

i32 iface_init(fnp_config* conf)
{
    u16 avail_ports= rte_eth_dev_count_avail();
    if (avail_ports < conf->ports_count)
    {
        printf("dpdk has %u avail ports found\n", avail_ports);
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    u32 socket_id = rte_socket_id();

    for (u16 id = 0; id < conf->ports_count; id++)
    {
        fnp_iface *iface = fnp_iface_get(id);
        port_config* pconf = &conf->ports[id];

        int ret = rte_eth_dev_info_get(id, &dev_info);
        if (ret != 0) {
            printf("fail to get device(port %u) info: %s\n", id, strerror(-ret));
            return -1;
        }
        printf("max_mtu: %u\n", dev_info.max_mtu);
        printf("min_mtu: %u\n", dev_info.min_mtu);
        printf("max_tx_queues: %u\n", dev_info.max_tx_queues);
        printf("max_rx_queues: %u\n", dev_info.max_rx_queues);

        iface->id = id;
        iface->ip = fnp_ipv4_ston(pconf->ip);
        iface->mask = fnp_ipv4_ston(pconf->ip_mask);
        iface->gateway = fnp_ipv4_ston(pconf->gateway);
        iface->rx_queue = fnp_pring_alloc(pconf->rx_ring_size);
        if (iface->rx_queue == NULL) {
            printf("create rx_queue error!\n");
            return -1;
        }

        iface->tx_queue = fnp_pring_alloc(pconf->tx_ring_size);
        if (iface->tx_queue == NULL) {
            fnp_pring_free(iface->rx_queue);
            printf("create tx_queue error!\n");
            return -1;
        }

        rte_eth_macaddr_get(id, &iface->mac);
        printf("local mac is "RTE_ETHER_ADDR_PRT_FMT"\n", RTE_ETHER_ADDR_BYTES(&iface->mac));

        struct rte_eth_conf eth_conf = {};
        ret = rte_eth_dev_configure(id, pconf->nb_rx_queue , pconf->nb_tx_queue, &eth_conf);
        if (ret != 0) {
            printf("fail to rte_eth_dev_configure: %s\n", strerror(-ret));
            return -1;
        }

        struct rte_eth_txconf txq_conf;
        txq_conf = dev_info.default_txconf;
        // txq_conf.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
        ret = rte_eth_tx_queue_setup(id, 0, pconf->nb_tx_desc, socket_id, &txq_conf);
        if (ret < 0) {
            printf("fail to rte_eth_tx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        struct rte_mempool *rx_pool = NULL;
        rx_pool = rte_pktmbuf_pool_create("RxMbufPool", pconf->rx_mbuf_pool_size, 256,
                                          0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (rx_pool == NULL) {
            printf("create rx_pool error!\n");
            return -1;
        }

        struct rte_eth_rxconf rxq_conf;
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = eth_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(id, 0, pconf->nb_rx_desc, socket_id, &rxq_conf, rx_pool);
        if (ret < 0) {
            printf("fail to rte_eth_rx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        ret = rte_eth_dev_start(id);
        if (ret != 0) {
            printf("fail to start port: %s\n", strerror(-ret));
            return -1;
        }

        /* Enable RX in promiscuous mode for the Ethernet device. */
        if (pconf->promiscuous) {
            ret = rte_eth_promiscuous_enable(id);
            printf("set port to promiscuous mode: %d\n", ret);
        }
    }

    return 0;
}



i32 dpdk_init(fnp_context* ctxt) {
    dpdk_config* dconf = &ctxt->conf.dpdk;
    i32 ret = rte_eal_init(dconf->argc, dconf->argv);
    if (ret < 0)
    {
        printf( "rte_eal_init error!\n");
        return -1;
    }

    u32 socket_id = rte_socket_id();

    /* init RTE timer library */
    rte_timer_subsystem_init();

    ctxt->pool = rte_pktmbuf_pool_create("FnpMbufPool", dconf->mbuf_pool_size, 256,
                                         0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (ctxt->pool == NULL)
    {
        printf("create gDirectPool failed!\n");
        return -1;
    }

    return iface_init(&ctxt->conf);
}

extern int arp_init();
extern void ipv4_init();
extern int tcp_init();

i32 fnp_init(char* path)
{
    fnp_config* conf = &fnp.conf;
    i32 ret = parse_fnp_config(path, conf);
    if (ret != 0)
    {
        printf("parse config error!\n");
        return -1;
    }

    ret = dpdk_init(&fnp);
    if (unlikely(ret < 0))
    {
        printf( "rte_eal_init error!\n");
        return -1;
    }

    if (arp_init() != 0) {
        return -1;
    }

    ipv4_init();

    if (tcp_init() != 0) {
        return -1;
    }

    if(rte_eal_remote_launch(fnp_rx_tx_worker, NULL, conf->worker1) != 0)
    {
        printf("launch %d error!\n", conf->worker1);
        return -1;
    }

    if(rte_eal_remote_launch(fnp_process_worker, NULL, conf->worker2) != 0)
    {
        printf("launch %d error!\n", conf->worker2);
        return -1;
    }

    return 0;
}