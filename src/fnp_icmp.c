
#include "fnp_icmp.h"
#include "fnp_ipv4.h"

#include <rte_icmp.h>

#define ICMP_ECHO_HDR_LEN 8

static u16 checksum(u16 *buf, int nbytes, u32 sum)
{
    for (int i = 0; i < nbytes / 2; i++)
        sum += buf[i];

    if (nbytes % 2)
        sum += ((u8 *)buf)[nbytes-1];

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);

    return (u16)~sum;
}

static u16 icmp_cksum(struct rte_icmp_hdr* hdr)
{
    hdr->icmp_cksum = 0;
    return checksum((u16*)hdr, ICMP_ECHO_HDR_LEN, 0);
}

void icmp_echo_reply(u16 iface_id, u32 dip, struct rte_icmp_hdr* req)
{
    struct rte_mbuf* m = fnp_alloc_mbuf();
    if(m == NULL)
    {
        printf("alloc icmp reply failed\n");
        return;
    }

    m->pkt_len = ICMP_ECHO_HDR_LEN;
    m->data_len = ICMP_ECHO_HDR_LEN;
    m->port = iface_id;
    struct rte_icmp_hdr* icmpHdr = rte_pktmbuf_mtod(m, struct rte_icmp_hdr*);
    icmpHdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmpHdr->icmp_code = 0;
    icmpHdr->icmp_ident = req->icmp_ident;
    icmpHdr->icmp_seq_nb = req->icmp_seq_nb;
    icmpHdr->icmp_cksum = icmp_cksum(icmpHdr);


    ipv4_send_mbuf(m, dip, IPPROTO_ICMP);
}

void icmp_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    struct rte_icmp_hdr* icmpHdr = rte_pktmbuf_mtod_offset(m, struct rte_icmp_hdr*, IPV4_HDR_LEN);

    switch(icmpHdr->icmp_type)
    {
        case RTE_IP_ICMP_ECHO_REQUEST:
        {
            icmp_echo_reply(m->port, ipv4Hdr->src_addr, icmpHdr);
            break;
        }
    }

    fnp_free_mbuf(m);
}



