#ifndef FNP_IPV4_H
#define FNP_IPV4_H

#include "fnp_socket.h"
#include "fnp_ifaddr.h"
#include <rte_ether.h>
#include <rte_mbuf.h>

#define IPV4_HDR_LEN 20

typedef void (*ipv4_input_func)(struct rte_mbuf *m);
typedef void (*ipv4_local_deliver_func)(struct rte_mbuf *m);

// IPv4发送缓存：
// - 无连接发送场景不需要它，直接调用 ipv4_send_default()
// - connected UDP/TCP 可以持有一个 cache
// - 初始 send 指向 default 实现；当出口 ifaddr、next hop、dmac 都明确后，
//   直接切换到 fast 实现，避免后续发送再做路径判断
typedef struct ipv4_tx_cache
{
    fsockaddr_t src;
    fsockaddr_t dst;
    fnp_ifaddr_t *ifaddr;       // 待确定：出口 ifaddr，包含了发送使用的设备
    u32 next_hop_be;            // 待确定：下一跳IP地址（大端序）
    struct rte_ether_addr dmac; // 待确定：下一跳MAC地址
    u8 proto;                   // 传输层协议号
    bool ready;                 // cache是否准备好，可以走fast路径
} ipv4_tx_cache_t;

void ipv4_init_tx_cache(ipv4_tx_cache_t *cache, u8 proto, fsockaddr_t *src, fsockaddr_t *dst);

int init_ipv4_layer(void);

int ipv4_register_input(u8 protocol, ipv4_input_func input);

int ipv4_register_local_deliver(ipv4_local_deliver_func input);

void ipv4_recv_mbuf(struct rte_mbuf *m);

// TUN 入口：前端应用写入一个完整 IPv4 包后，从这里注入 IPv4 层。
void ipv4_tun_input(struct rte_mbuf *m);

// 通用默认发送入口：
// - ICMP、无连接UDP、临时TCP控制包等无状态发送场景直接调用
// - 内部会自动完成本地递交 / 路由查找 / ARP 查询 / L2 发送
bool ipv4_send_default(struct rte_mbuf *m, u8 proto, const fsockaddr_t *local, const fsockaddr_t *remote);

// connected socket统一发送入口，内部直接调用 cache->send。
bool ipv4_send_mbuf_with_cache(ipv4_tx_cache_t *cache, struct rte_mbuf *m);

#endif // FNP_IPV4_H
