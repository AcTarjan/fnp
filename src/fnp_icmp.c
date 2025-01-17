#include "fnp_ipv4.h"

#include "fnp_init.h"
#include <rte_icmp.h>
#include <rte_ip.h>

#define ICMP_HDR_LEN 8

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

void icmp_echo_reply(u16 iface_id, u32 dip, struct rte_mbuf* req)
{
    struct rte_icmp_hdr* req_hdr = rte_pktmbuf_mtod(req, struct rte_icmp_hdr*);
    u8* req_data = (u8*)rte_pktmbuf_adj(req, ICMP_HDR_LEN);
    int data_len = rte_pktmbuf_data_len(req);

    struct rte_mbuf* m = fnp_mbuf_alloc();
    if(m == NULL)
    {
        printf("alloc icmp reply failed\n");
        return;
    }

    m->port = iface_id;
    struct rte_icmp_hdr* hdr = (struct rte_icmp_hdr*)rte_pktmbuf_append(m, ICMP_HDR_LEN);
    hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    hdr->icmp_code = 0;
    hdr->icmp_ident = req_hdr->icmp_ident;
    hdr->icmp_seq_nb = req_hdr->icmp_seq_nb;
    hdr->icmp_cksum = 0;
    if (data_len > 0)
    {
        u8* new_data = (u8*)rte_pktmbuf_append(m, data_len);
        rte_memcpy(new_data, req_data, data_len);
    }
    hdr->icmp_cksum = checksum((u16*)hdr, ICMP_HDR_LEN + data_len, 0);


    ipv4_send_mbuf(m, IPPROTO_ICMP, dip);
}

void icmp_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr* ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    int ip_hdr_len = rte_ipv4_hdr_len(ipv4Hdr);
    struct rte_icmp_hdr* icmpHdr = (struct rte_icmp_hdr*)rte_pktmbuf_adj(m, ip_hdr_len);

    switch(icmpHdr->icmp_type)
    {
        case RTE_IP_ICMP_ECHO_REQUEST:
        {
            icmp_echo_reply(m->port, ipv4Hdr->src_addr, m);
            break;
        }
    }

    fnp_mbuf_free(m);
}



