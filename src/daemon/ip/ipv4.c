#include "ipv4.h"

#include "fnp_context.h"
#include "fnp_worker.h"
#include "ether.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"
#include "fsocket.h"

#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ip.h>


typedef void (*ipv4_recv_handler)(struct rte_mbuf*);
static ipv4_recv_handler handlers[IPPROTO_MAX];

static inline void ipv4_register(int proto, ipv4_recv_handler h)
{
    handlers[proto] = h;
}

static void ipv4_recv_default(struct rte_mbuf* m)
{
    free_mbuf(m); // 默认处理，直接释放
}

void init_ipv4_layer()
{
    for (int i = 0; i < IPPROTO_MAX; i++)
    {
        handlers[i] = ipv4_recv_default;
    }

    ipv4_register(IPPROTO_ICMP, icmp_recv_mbuf);
    ipv4_register(IPPROTO_TCP, tcp_recv_mbuf_from_ipv4);
    ipv4_register(IPPROTO_UDP, udp_recv_mbuf_from_ipv4);
}


void ipv4_recv_mbuf(struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);

    handlers[hdr->next_proto_id](m);
}

static inline void compute_cksum(struct rte_ipv4_hdr* hdr, struct rte_mbuf* m)
{
    switch (hdr->next_proto_id)
    {
    case IPPROTO_TCP:
        {
            struct rte_tcp_hdr* tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, IPV4_HDR_LEN);
            tcp_hdr->cksum = rte_ipv4_udptcp_cksum(hdr, tcp_hdr);
            break;
        }
    case IPPROTO_UDP:
        {
            struct rte_udp_hdr* udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, IPV4_HDR_LEN);
            udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(hdr, udp_hdr);
            break;
        }
    }

    // 计算ipv4头部校验和
    hdr->hdr_checksum = rte_ipv4_cksum(hdr);
}

// ipv4_send_mbuf
// 目前不存在iface为NULL的情况，如果为NULL，需要根据目的ip进行路由
void ipv4_send_mbuf(struct rte_mbuf* m, u8 proto, u32 rip)
{
    // 查询路由表，选择出口网卡
    fnp_iface_t* iface = find_iface_for_outlet(rip);
    m->port = iface->port;

    struct rte_ipv4_hdr* hdr = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0; //禁止分片
    hdr->time_to_live = 64;
    hdr->next_proto_id = proto;
    hdr->src_addr = iface->ip;
    hdr->dst_addr = rip;
    hdr->hdr_checksum = 0; // 硬件计算

    if (1)
    {
        // 硬件计算校验和，UDP/TCP和
        m->ol_flags = (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4);
        m->l3_len = IPV4_HDR_LEN;

        // 部分网卡需要软件计算伪首部
        if (likely(proto == IPPROTO_UDP))
        {
            m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
            struct rte_udp_hdr* udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr*, IPV4_HDR_LEN);
            udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(hdr, m->ol_flags);
        }
        else if (proto == IPPROTO_TCP)
        {
            m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
            struct rte_tcp_hdr* tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr*, IPV4_HDR_LEN);
            tcp_hdr->cksum = rte_ipv4_phdr_cksum(hdr, m->ol_flags);
        }
    }
    else
    {
        // 注意：如果使用软件计算校验和，禁止配置开启网卡的硬件校验功能
        // 已知的问题: 软件计算校验和，但是却配置了m->ol_flags = RTE_MBUF_F_TX_UDP_CKSUM
        // 会导致ipv4首部的fragment_offset乱码，导致对端识别到异常分段
        compute_cksum(hdr, m);
    }


    // 查找下一跳
    u32 next_hop = find_next_hop(iface, rip);

    arp_entry_t* e = arp_lookup(next_hop);
    if (unlikely(e == NULL))
    {
        printf("can't find arp entry for %x to %x\n", rip, next_hop);
        arp_pend_mbuf(iface, next_hop, m);
        return;
    }

    // 找到arp表项, 直接发送
    ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
}

// ipv4_fast_send_mbuf
// 用于已知目的ip情况，加速连接的数据发送
void ipv4_fast_send_mbuf(fsocket_t* socket, struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* hdr = (struct rte_ipv4_hdr*)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = socket->proto;
    hdr->src_addr = socket->local.ip;
    hdr->dst_addr = socket->remote.ip;
    hdr->hdr_checksum = 0; // 硬件计算
    compute_cksum(hdr, m);

    // m->port = socket->iface->port;
    // ether_send_mbuf(m, &socket->next_mac, RTE_ETHER_TYPE_IPV4);
}
