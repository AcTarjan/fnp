#ifndef FNP_IPV4_H
#define FNP_IPV4_H

#include "fnp_socket.h"
#include "fnp_network.h"
#include <rte_ether.h>
#include <rte_mbuf.h>

#define IPV4_HDR_LEN 20

typedef void (*ipv4_input_func)(struct rte_mbuf *m);
typedef void (*ipv4_local_deliver_func)(struct rte_mbuf *m);

typedef struct ipv4_tx_cache ipv4_tx_cache_t;
typedef void (*ipv4_tx_send_func)(ipv4_tx_cache_t *cache,
                                  struct rte_mbuf *m,
                                  u8 proto,
                                  const fsockaddr_t *local,
                                  const fsockaddr_t *remote);

// IPv4发送缓存：
// - 无连接发送场景不需要它，直接调用 ipv4_send_default()
// - connected UDP/TCP 可以持有一个 cache
// - 初始 send 指向 default 实现；当出口 ifaddr、next hop、dmac 都明确后，
//   直接切换到 fast 实现，避免后续发送再做路径判断
struct ipv4_tx_cache
{
    ipv4_tx_send_func send;
    fnp_ifaddr_t *ifaddr;
    u32 next_hop_be;
    struct rte_ether_addr dmac;
    fsockaddr_t local;
    fsockaddr_t remote;
    u8 dmac_ready : 1;
};

int init_ipv4_layer(void);

int ipv4_register_input(u8 protocol, ipv4_input_func input);

int ipv4_register_local_deliver(ipv4_local_deliver_func input);

void ipv4_recv_mbuf(struct rte_mbuf *m);

// TUN 入口：前端应用写入一个完整 IPv4 包后，从这里注入 IPv4 层。
void ipv4_tun_input(struct rte_mbuf *m);

// 通用默认发送入口：
// - ICMP、无连接UDP、临时TCP控制包等无状态发送场景直接调用
// - 内部会自动完成本地递交 / 路由查找 / ARP 查询 / L2 发送
void ipv4_send_default(struct rte_mbuf *m, u8 proto, const fsockaddr_t *local, const fsockaddr_t *remote);

// 初始化connected socket持有的IPv4发送缓存。
void ipv4_tx_cache_init(ipv4_tx_cache_t *cache);

// connected socket统一发送入口，内部直接调用 cache->send。
void ipv4_tx_cache_send(ipv4_tx_cache_t *cache,
                        struct rte_mbuf *m,
                        u8 proto,
                        const fsockaddr_t *local,
                        const fsockaddr_t *remote);

// 兼容旧调用方的轻量包装：
// 仅指定目的IP时，源地址由路由模块决定。
void ipv4_send_mbuf(struct rte_mbuf *m, u8 proto, u32 rip);

// 用于RAW socket等原始L3报文发送，要求mbuf起始位置已经是ipv4 header
void ipv4_send_raw_mbuf(struct rte_mbuf *m);

#endif // FNP_IPV4_H
