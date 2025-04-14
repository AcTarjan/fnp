#include "ipv4.h"

#include "fnp_context.h"
#include "ether.h"
#include "arp.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"

#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ip.h>

typedef void (*ipv4_recv_handler)(struct rte_mbuf *);
static ipv4_recv_handler handlers[IPPROTO_MAX];

static inline void ipv4_register(int proto, ipv4_recv_handler h)
{
    handlers[proto] = h;
}

void ipv4_recv_default(struct rte_mbuf *m)
{
    rte_pktmbuf_free(m); // 默认处理，直接释放
}

void init_ipv4_layer()
{
    for (int i = 0; i < IPPROTO_MAX; i++)
    {
        handlers[i] = ipv4_recv_default;
    }

    ipv4_register(IPPROTO_ICMP, icmp_recv_mbuf);
    ipv4_register(IPPROTO_TCP, tcp_recv_mbuf);
    ipv4_register(IPPROTO_UDP, udp_recv_from_net);
}

void ipv4_recv_mbuf(fnp_iface_t *iface, struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);

    if (hdr->dst_addr != iface->ip)
    {
        free_mbuf(m);
        return;
    }

    // 处理IP数据包
    handlers[hdr->next_proto_id](m);
}

static inline void compute_cksum(struct rte_ipv4_hdr *hdr, struct rte_mbuf *m)
{
    switch (hdr->next_proto_id)
    {
    case IPPROTO_TCP:
    {
        struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, IPV4_HDR_LEN);
        tcp_hdr->cksum = rte_ipv4_udptcp_cksum(hdr, tcp_hdr);
        break;
    }
    case IPPROTO_UDP:
    {
        struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, IPV4_HDR_LEN);
        udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(hdr, udp_hdr);
        break;
    }
    }

    // 计算ipv4头部校验和
    hdr->hdr_checksum = rte_ipv4_cksum(hdr);

    //    printf("%u %u\n", hdr->hdr_checksum, tcphdr->cksum);
    //    m->ol_flags |= (struct rte_mbuf_F_TX_IP_CKSUM | struct rte_mbuf_F_TX_IPV4);
    //    m->l3_len = IPV4_HDR_LEN;
}

// ipv4_send_mbuf
// 目前不存在iface为NULL的情况，如果为NULL，需要根据目的ip进行路由
void ipv4_send_mbuf(struct rte_mbuf *m, u8 proto, u32 rip)
{
    fnp_iface_t *iface = find_iface_for_outlet(rip);

    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = proto;
    hdr->src_addr = iface->ip;
    hdr->dst_addr = rip;
    hdr->hdr_checksum = 0; // 硬件计算

    compute_cksum(hdr, m);

    u32 next_hop = find_next_hop(iface, rip);
    arp_pend_mbuf(iface, m, next_hop);
}

// ipv4_fast_send_mbuf
// 用于已知目的ip情况，加速连接的数据发送
void ipv4_fast_send_mbuf(fnp_socket_t *socket, struct rte_mbuf *m)
{
    fnp_sockaddr_t *addr = &socket->addr;

    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = addr->proto;
    hdr->src_addr = addr->lip;
    hdr->dst_addr = addr->rip;
    hdr->hdr_checksum = 0; // 硬件计算
    compute_cksum(hdr, m);

    ether_send_mbuf(socket->iface, m, &socket->next_mac, RTE_ETHER_TYPE_IPV4);
}