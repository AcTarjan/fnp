#include "fnp_context.h"

#include "fnp_error.h"

#include "fnp_msg.h"
#include "arp.h"
#include "ipv4.h"
#include "tcp.h"
#include "quic.h"
#include "fnp_socket.h"

#include <rte_pdump.h>

#include "fnp_worker.h"

fnp_context_t fnp;

i32 init_dpdk(dpdk_config* conf)
{
    i32 ret = rte_eal_init(conf->argc, conf->argv);
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

    return FNP_OK;
}


i32 init_fnp_daemon(char* path)
{
    fnp_config* conf = &fnp.conf;
    i32 ret = parse_fnp_config(path, conf);
    if (ret != 0)
    {
        FNP_ERR("parse config error!\n");
        return -1;
    }

    ret = init_dpdk(&conf->dpdk);
    CHECK_RET(ret);

    init_fmsg_center();

    /* 初始化fnp_worker, 在这里调用主要是为了初始化mbufpool */
    ret = init_fnp_worker(&conf->worker);
    CHECK_RET(ret);

    ret = init_fnp_iface_layer(conf);
    CHECK_RET(ret);

    ret = init_arp_layer();
    CHECK_RET(ret);

    init_ipv4_layer();

    init_tcp_layer();


    ret = init_master();
    CHECK_RET(ret);


    return FNP_OK;
}
