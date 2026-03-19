#ifndef FNP_IPV4_H
#define FNP_IPV4_H

#include "../../common/fnp_socket.h"
#include <rte_mbuf.h>

#define IPV4_HDR_LEN 20

typedef void (*ipv4_input_func)(struct rte_mbuf* m);
typedef void (*ipv4_local_deliver_func)(struct rte_mbuf* m);

int init_ipv4_layer(void);

int ipv4_register_input(u8 protocol, ipv4_input_func input);

int ipv4_register_local_deliver(ipv4_local_deliver_func input);

void ipv4_recv_mbuf(struct rte_mbuf* m);

// 用于目的ip确定的sock来快速发送应用数据
// 避免查找路由表和arp表
void ipv4_fast_send_mbuf(struct rte_mbuf* m, const fsockaddr_t* local, const fsockaddr_t* remote);

// 用于icmp或者目的ip不确定的sock的数据发送
void ipv4_send_mbuf(struct rte_mbuf* m, u8 proto, u32 rip);

// 用于RAW socket等原始L3报文发送，要求mbuf起始位置已经是ipv4 header
void ipv4_send_raw_mbuf(struct rte_mbuf* m);

#endif // FNP_IPV4_H
