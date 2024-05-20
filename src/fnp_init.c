#include "fnp_init.h"

#include <rte_ethdev.h>

fnp_conf_t conf;

i32 iface_init(fnp_conf_t* conf)
{
    u16 avail_ports= rte_eth_dev_count_avail();
    if (avail_ports < conf->ifaces_num)
    {
        printf("dpdk has %u avail ports found\n", avail_ports);
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    u32 socket_id = rte_socket_id();

    for (u16 iface_id = 0; iface_id < conf->ifaces_num; iface_id++)
    {
        fnp_iface_t *iface = fnp_get_iface(0);
        iface->rx_queue = fnp_alloc_ring(4096 * 8);
        if (iface->rx_queue == NULL) {
            printf("create rx_queue error!\n");
            return -1;
        }

        iface->tx_queue = fnp_alloc_ring(4096 * 8);
        if (iface->tx_queue == NULL) {
            fnp_free_ring(iface->rx_queue);
            printf("create tx_queue error!\n");
            return -1;
        }
        int ret = rte_eth_dev_info_get(iface_id, &dev_info);
        if (ret != 0) {
            printf("fail to get device(port %u) info: %s\n", iface_id, strerror(-ret));
            return -1;
        }
        printf("max_mtu: %u\n", dev_info.max_mtu);
        printf("min_mtu: %u\n", dev_info.min_mtu);
        printf("max_tx_queues: %u\n", dev_info.max_tx_queues);
        printf("max_rx_queues: %u\n", dev_info.max_rx_queues);

        rte_eth_macaddr_get(iface_id, &iface->mac);
        printf("local mac is "RTE_ETHER_ADDR_PRT_FMT"\n", RTE_ETHER_ADDR_BYTES(&iface->mac));

        struct rte_eth_conf eth_conf = {};
        ret = rte_eth_dev_configure(iface_id, 1, 1, &eth_conf);
        if (ret != 0) {
            printf("fail to rte_eth_dev_configure: %s\n", strerror(-ret));
            return -1;
        }

        struct rte_eth_txconf txq_conf;
        txq_conf = dev_info.default_txconf;
        // txq_conf.offloads = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_OUTER_UDP_CKSUM;
        ret = rte_eth_tx_queue_setup(iface_id, 0, 2048, socket_id, &txq_conf);
        if (ret < 0) {
            printf("fail to rte_eth_tx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        struct rte_mempool *rx_pool = NULL;
        rx_pool = rte_pktmbuf_pool_create("RxMbufPool", 4095, 256,
                                          0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (rx_pool == NULL) {
            printf("create rx_pool error!\n");
            return -1;
        }

        struct rte_eth_rxconf rxq_conf;
        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = eth_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(iface_id, 0, 2048, socket_id, &rxq_conf, rx_pool);
        if (ret < 0) {
            printf("fail to rte_eth_rx_queue_setup: %s\n", strerror(-ret));
            return -1;
        }

        ret = rte_eth_dev_start(iface_id);
        if (ret != 0) {
            printf("fail to start port: %s\n", strerror(-ret));
            return -1;
        }

        /* Enable RX in promiscuous mode for the Ethernet device. */
        if (conf->dpdk.promiscuous) {
            ret = rte_eth_promiscuous_enable(iface_id);
            printf("set port to promiscuous mode: %d\n", ret);
        }
    }

    return 0;
}


static i32 setup_dpdk_args(dpdk_conf_t *conf, char** argv)
{
    i32 n = 0;
    char temp[32] = {0};

    argv[n++] = strdup("fnp");

    if (conf->lcore_list) {
        sprintf(temp, "-l %s", conf->lcore_list);
        argv[n++] = strdup(temp);
    }

    for (i32 i = 0; i < n; i++)
        printf("%s ", argv[i]);
    printf("\n");

    return n;
}

i32 dpdk_init(fnp_conf_t* conf) {
    char* argv[32];
    i32 argc = setup_dpdk_args(&conf->dpdk, argv);

    i32 ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        printf( "rte_eal_init error!\n");
        return -1;
    }

    u32 socket_id = rte_socket_id();

    /* init RTE timer library */
    rte_timer_subsystem_init();

    conf->directPool = rte_pktmbuf_pool_create("gDirectPool", 4096*2-1,256,
                                          0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (conf->directPool == NULL)
    {
        printf("create gDirectPool failed!\n");
        return -1;
    }

    return iface_init(conf);
}

void fnp_conf_init(fnp_conf_t* conf)
{
    conf->dpdk.lcore_list =  "2,3,4,5";
    conf->dpdk.main_lcore =  2;
    conf->ifaces_num =  1;
    conf->ifaces[0].id =  0;
    conf->ifaces[0].ip =  fnp_ipv4_ston("192.168.222.66");
    conf->ifaces[0].mask =  fnp_ipv4_ston("255.255.255.0");
    conf->ifaces[0].gateway =  fnp_ipv4_ston("192.168.222.254");
    conf->worker1 = 3;
    conf->worker2 = 4;
    conf->worker3 = 5;
}

i32 fnp_process_worker();

i32 fnp_rx_tx_worker();

i32 fnp_timer_worker();

i32 fnp_init(char* path)
{
    fnp_conf_init(&conf);

    i32 ret = dpdk_init(&conf);
    if (unlikely(ret < 0))
    {
        printf( "rte_eal_init error!\n");
        return -1;
    }

    conf.arpTbl = fnp_alloc_hash(256, 4);
    if(unlikely(conf.arpTbl == NULL)){
        printf( "alloc arp table error!\n");
        return -1;
    }

    conf.tcpSockTbl = fnp_alloc_hash(1024, 12);
    if(unlikely(conf.tcpSockTbl == NULL)){
        printf( "alloc tcp sock table error!\n");
        return -1;
    }

    if(rte_eal_remote_launch(fnp_rx_tx_worker, NULL, conf.worker1) != 0)
    {
        printf( "launch %d error!\n", conf.worker1);
        return -1;
    }

    if(unlikely(rte_eal_remote_launch(fnp_process_worker, NULL, conf.worker2) != 0))
    {
        printf( "launch %d error!\n", conf.worker2);
        return -1;
    }

    if(unlikely(rte_eal_remote_launch(fnp_timer_worker, NULL, conf.worker3) != 0))
    {
        printf( "launch %d error!\n", conf.worker3);
        return -1;
    }

    return 0;
}