#ifndef FNP_TUN_H
#define FNP_TUN_H

#include "fnp_network.h"

#include <rte_mbuf.h>

int tun_module_init(void);

// 设备输出接口：给 tun device 发送完整 IPv4 包。
void tun_device_send(fnp_device_t* dev,
                     struct rte_mbuf* m,
                     const struct rte_ether_addr* dmac);

#endif // FNP_TUN_H
