#ifndef FNP_IPV4_H
#define FNP_IPV4_H

#include "../../common/fnp_socket.h"
#include <rte_mbuf.h>

#define IPV4_HDR_LEN 20

void init_ipv4_layer();

void ipv4_recv_mbuf(struct rte_mbuf* m);

// 用于目的ip确定的sock来快速发送应用数据
// 避免查找路由表和arp表
void ipv4_fast_send_mbuf(fsocket_t* sock, struct rte_mbuf* m);

// 用于icmp或者目的ip不确定的sock的数据发送
void ipv4_send_mbuf(struct rte_mbuf* m, u8 proto, u32 rip);

#endif // FNP_IPV4_H
