#include <unistd.h>
#include "fnp_ipv4.h"
#include "fnp_tcp.h"
#include "fnp_arp.h"
#include "fnp_ether.h"
#include "fnp_icmp.h"


void ipv4_recv_mbuf(rte_mbuf *m, u64 tsc)
{
    fnp_iface_t* iface = fnp_get_iface(m->port);
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);

    if(hdr->dst_addr != iface->ip)
    {
        rte_pktmbuf_free(m);
        return ;
    }

    switch (hdr->next_proto_id)
    {
        case IPPROTO_UDP:
        {
//            udp_recv_mbuf(m);
            break ;
        }
        case IPPROTO_TCP:
        {
            tcp_recv_mbuf(m);
            break ;
        }
        case IPPROTO_ICMP:
        {
            icmp_recv_mbuf(m);
            break;
        }
        default:
        {
            rte_pktmbuf_free(m);
        }
    }

}

void ipv4_send_mbuf(rte_mbuf *m, u32 rip, u8 proto)
{
    fnp_iface_t* iface = fnp_get_iface(m->port);
    struct rte_ipv4_hdr* hdr = (struct rte_ipv4_hdr*) rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    struct rte_tcp_hdr* tcphdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr* ,IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = proto;
    hdr->src_addr = iface->ip;
    hdr->dst_addr = rip;
    hdr->hdr_checksum = 0;				//硬件计算

    tcphdr->cksum = rte_ipv4_udptcp_cksum(hdr, tcphdr);
    hdr->hdr_checksum = rte_ipv4_cksum(hdr);


//    printf("%u %u\n", hdr->hdr_checksum, tcphdr->cksum);
//    m->ol_flags |= (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4);
//    m->l3_len = IPV4_HDR_LEN;

    u32 next_ip = rip;
    if((iface->ip & iface->mask) != (rip & iface->mask))
    {
        next_ip = iface->gateway;
    }

    arp_send_mbuf(m, next_ip);
}