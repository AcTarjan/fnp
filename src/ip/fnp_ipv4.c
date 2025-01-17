#include "fnp_ipv4.h"
#include "fnp_arp.h"
#include "tcp.h"
#include "fnp_udp.h"
#include "fnp_init.h"

#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ip.h>

typedef void (*ipv4_recv_handler)(struct rte_mbuf*);
static ipv4_recv_handler handlers[IPPROTO_MAX];

void ipv4_register(int proto, ipv4_recv_handler h) {
    handlers[proto] = h;
}

void ipv4_recv_default(struct rte_mbuf* m) {
    rte_pktmbuf_free(m);
}

extern void icmp_recv_mbuf(struct rte_mbuf *m);
void ipv4_init() {
    for(int i = 0; i < IPPROTO_MAX; i++) {
        handlers[i] = ipv4_recv_default;
    }
    ipv4_register(IPPROTO_ICMP, icmp_recv_mbuf);
    ipv4_register(IPPROTO_TCP, tcp_recv_mbuf);
    ipv4_register(IPPROTO_UDP, udp_recv_mbuf);
}

void ipv4_recv_mbuf(struct rte_mbuf *m, u64 tsc)
{
    fnp_iface_t* iface = fnp_iface_get(m->port);
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);

    if(hdr->dst_addr != iface->ip)
    {
        rte_pktmbuf_free(m);
        return ;
    }

    handlers[hdr->next_proto_id](m);
}

void ipv4_send_mbuf(struct rte_mbuf *m, u8 proto, u32 dst_ip)
{
    fnp_iface_t* iface = fnp_iface_get(m->port);
    struct rte_ipv4_hdr* hdr = (struct rte_ipv4_hdr*) rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = proto;
    hdr->src_addr = iface->ip;
    hdr->dst_addr = dst_ip;
    hdr->hdr_checksum = 0;				//硬件计算

    switch (proto)
    {
        case IPPROTO_TCP:
            {
                struct rte_tcp_hdr* tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr* ,IPV4_HDR_LEN);
                tcp_hdr->cksum = rte_ipv4_udptcp_cksum(hdr, tcp_hdr);
                break;
            }
        case IPPROTO_UDP:
            {
                struct rte_udp_hdr* udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr* ,IPV4_HDR_LEN);
                udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(hdr, udp_hdr);
                break;
            }
    }
    hdr->hdr_checksum = rte_ipv4_cksum(hdr);


//    printf("%u %u\n", hdr->hdr_checksum, tcphdr->cksum);
//    m->ol_flags |= (struct rte_mbuf_F_TX_IP_CKSUM | struct rte_mbuf_F_TX_IPV4);
//    m->l3_len = IPV4_HDR_LEN;

    u32 next_ip = dst_ip;
    if((iface->ip & iface->mask) != (dst_ip & iface->mask))
    {
        next_ip = iface->gateway;
    }

    arp_send_mbuf(m, next_ip);
}