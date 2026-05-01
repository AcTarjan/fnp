#ifndef FNP_ETHER_H
#define FNP_ETHER_H

#include "fnp_device.h"

#include <rte_ether.h>

typedef void (*ether_input_func)(struct rte_mbuf* m);

int init_ether_layer(void);

int init_ether_device_layer(fnp_config *conf);

int ether_register_input(u16 ethertype, ether_input_func input);

void ether_recv_mbuf(struct rte_mbuf* m);

// IPv4 通过二层设备发送时的统一出口：
// - 输入 mbuf 起始位置是完整 IPv4 包
// - 负责补以太网头并交给具体 device 输出
bool ether_device_send(fnp_device_t* dev, struct rte_mbuf* m, const struct rte_ether_addr* dmac);

// 二层统一发送入口：
// - 输入 mbuf 不带以太网头
// - 根据 device 类型补二层头，并把完整二层帧发往 ethernet/tap 设备
bool ether_send_mbuf(struct rte_mbuf* m, fnp_device_t* dev, struct rte_ether_addr* dmac, u16 type);

#endif //FNP_ETHER_H
