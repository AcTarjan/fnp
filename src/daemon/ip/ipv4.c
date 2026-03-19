#include "ipv4.h"

#include "fnp_context.h"
#include "fnp_worker.h"
#include "ether.h"
#include "arp.h"
#include "route.h"
#include "fsocket.h"

#include <rte_udp.h>
#include <rte_ip.h>

static ipv4_input_func ipv4_input_table[UINT8_MAX + 1];
static ipv4_local_deliver_func ipv4_local_deliver_handler;

static void ipv4_drop_input(struct rte_mbuf *m)
{
    free_mbuf(m);
}

static void ipv4_ignore_local_deliver(struct rte_mbuf *m)
{
    (void)m;
}

static inline bool ipv4_is_local_packet(const struct rte_ipv4_hdr *hdr)
{
    return hdr != NULL && route_lookup_local(hdr->dst_addr) != NULL;
}

int init_ipv4_layer(void)
{
    for (u32 i = 0; i <= UINT8_MAX; ++i)
    {
        ipv4_input_table[i] = ipv4_drop_input;
    }

    ipv4_local_deliver_handler = ipv4_ignore_local_deliver;
    return ether_register_input(RTE_ETHER_TYPE_IPV4, ipv4_recv_mbuf);
}

int ipv4_register_input(u8 protocol, ipv4_input_func input)
{
    ipv4_input_table[protocol] = input == NULL ? ipv4_drop_input : input;
    return FNP_OK;
}

int ipv4_register_local_deliver(ipv4_local_deliver_func input)
{
    ipv4_local_deliver_handler = input == NULL ? ipv4_ignore_local_deliver : input;
    return FNP_OK;
}

static void raw_local_deliver(struct rte_mbuf *m)
{
    ipv4_local_deliver_handler(m);
}

static void transport_local_deliver(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    ipv4_input_table[hdr->next_proto_id](m);
}

static void ip_local_deliver(struct rte_mbuf *m)
{
    raw_local_deliver(m);

    transport_local_deliver(m);
}

void ipv4_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    if (unlikely(!ipv4_is_local_packet(hdr)))
    {
        // Forwarding path is not implemented yet.
        free_mbuf(m);
        return;
    }

    ip_local_deliver(m);
}

static inline void compute_cksum(struct rte_ipv4_hdr *hdr, struct rte_mbuf *m)
{
    u16 l3_len = rte_ipv4_hdr_len(hdr);
    switch (hdr->next_proto_id)
    {
    case IPPROTO_UDP:
    {
        struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, l3_len);
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(hdr, udp_hdr);
        break;
    }
    }

    // 计算ipv4头部校验和
    hdr->hdr_checksum = rte_ipv4_cksum(hdr);
}

// ipv4_send_mbuf
// 目前不存在iface为NULL的情况，如果为NULL，需要根据目的ip进行路由
void ipv4_send_mbuf(struct rte_mbuf *m, u8 proto, u32 rip)
{
    fnp_route_result_t route_result;
    if (unlikely(route_lookup(rip, &route_result) != FNP_OK || route_result.ifaddr == NULL))
    {
        free_mbuf(m);
        return;
    }

    m->port = route_result.ifaddr->dev->port_id;

    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0; // 禁止分片
    hdr->time_to_live = 64;
    hdr->next_proto_id = proto;
    hdr->src_addr = route_result.pref_src_be;
    hdr->dst_addr = rip;
    hdr->hdr_checksum = 0; // 硬件计算

    if (1)
    {
        // 硬件计算IPv4和UDP校验和
        m->ol_flags = (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4);
        m->l3_len = IPV4_HDR_LEN;

        // 部分网卡需要软件计算伪首部
        if (likely(proto == IPPROTO_UDP))
        {
            m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
            struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, IPV4_HDR_LEN);
            udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(hdr, m->ol_flags);
        }
    }
    else
    {
        // 注意：如果使用软件计算校验和，禁止配置开启网卡的硬件校验功能
        // 已知的问题: 软件计算校验和，但是却配置了m->ol_flags = RTE_MBUF_F_TX_UDP_CKSUM
        // 会导致ipv4首部的fragment_offset乱码，导致对端识别到异常分段
        compute_cksum(hdr, m);
    }

    arp_entry_t *e = arp_lookup(route_result.ifaddr, route_result.next_hop_be);
    if (unlikely(e == NULL))
    {
        arp_pend_mbuf(route_result.ifaddr, route_result.next_hop_be, m);
        return;
    }

    ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
}

void ipv4_send_raw_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u16 total_len = rte_be_to_cpu_16(hdr->total_length);
    u16 header_len = rte_ipv4_hdr_len(hdr);
    if (unlikely(total_len < header_len || total_len > m->pkt_len))
    {
        free_mbuf(m);
        return;
    }

    if (unlikely(total_len < m->pkt_len))
    {
        rte_pktmbuf_trim(m, m->pkt_len - total_len);
    }

    fnp_ifaddr_t *preferred_ifaddr = NULL;
    if (hdr->src_addr != 0)
    {
        preferred_ifaddr = lookup_ifaddr(hdr->src_addr);
        if (preferred_ifaddr == NULL)
        {
            free_mbuf(m);
            return;
        }
    }

    fnp_route_result_t route_result;
    int ret = preferred_ifaddr != NULL ? route_lookup_with_ifaddr(preferred_ifaddr, hdr->dst_addr, &route_result) : route_lookup(hdr->dst_addr, &route_result);
    if (unlikely(ret != FNP_OK || route_result.ifaddr == NULL))
    {
        free_mbuf(m);
        return;
    }

    if (hdr->src_addr == 0)
    {
        hdr->src_addr = route_result.pref_src_be;
    }

    m->port = route_result.ifaddr->dev->port_id;
    compute_cksum(hdr, m);

    arp_entry_t *e = arp_lookup(route_result.ifaddr, route_result.next_hop_be);
    if (unlikely(e == NULL))
    {
        arp_pend_mbuf(route_result.ifaddr, route_result.next_hop_be, m);
        return;
    }

    ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
}

// ipv4_fast_send_mbuf
// 用于已知目的ip情况，加速连接的数据发送
void ipv4_fast_send_mbuf(struct rte_mbuf *m, const fsockaddr_t *local, const fsockaddr_t *remote)
{
    if (unlikely(local == NULL || remote == NULL))
    {
        free_mbuf(m);
        return;
    }

    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = IPPROTO_UDP;
    hdr->src_addr = local->ip;
    hdr->dst_addr = remote->ip;
    hdr->hdr_checksum = 0; // 硬件计算
    compute_cksum(hdr, m);

    // m->port = socket->iface->port;
    // ether_send_mbuf(m, &socket->next_mac, RTE_ETHER_TYPE_IPV4);
}
