#include "icmp.h"
#include "ipv4.h"
#include "fnp_worker.h"

#include <rte_icmp.h>
#include <rte_ip.h>

#define ICMP_HDR_LEN 8
#define ICMP_PORT_UNREACH_TYPE 3
#define ICMP_PORT_UNREACH_CODE 3

static u16 checksum(u16* buf, int nbytes, u32 sum)
{
    for (int i = 0; i < nbytes / 2; i++)
        sum += buf[i];

    if (nbytes % 2)
        sum += ((u8*)buf)[nbytes - 1];

    while (sum >> 16)
        sum = (sum >> 16) + (sum & 0xffff);

    return (u16)~sum;
}

static void icmp_echo_reply(struct rte_mbuf* orig_mbuf, u32 dip)
{
    struct rte_icmp_hdr* req_hdr = rte_pktmbuf_mtod(orig_mbuf, struct rte_icmp_hdr *);
    u8* req_data = (u8*)rte_pktmbuf_adj(orig_mbuf, ICMP_HDR_LEN);
    int data_len = rte_pktmbuf_data_len(orig_mbuf);

    struct rte_mbuf* m = alloc_mbuf();
    if (m == NULL)
    {
        printf("alloc icmp reply failed\n");
        return;
    }

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

void icmp_recv_mbuf(struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    int ip_hdr_len = rte_ipv4_hdr_len(ipv4Hdr);
    struct rte_icmp_hdr* icmpHdr = (struct rte_icmp_hdr*)rte_pktmbuf_adj(m, ip_hdr_len);

    switch (icmpHdr->icmp_type)
    {
    case RTE_IP_ICMP_ECHO_REQUEST:
        {
            icmp_echo_reply(m, ipv4Hdr->src_addr);
            break;
        }
    }

    free_mbuf(m);
}

void icmp_send_port_unreachable(struct rte_mbuf* orig_mbuf)
{
    struct rte_mbuf* m = alloc_mbuf();
    if (m == NULL)
    {
        printf("alloc icmp port unreachable failed\n");
        return;
    }

    // ICMP 头
    struct rte_icmp_hdr* hdr = (struct rte_icmp_hdr*)rte_pktmbuf_append(m, ICMP_HDR_LEN);
    hdr->icmp_type = ICMP_PORT_UNREACH_TYPE;
    hdr->icmp_code = ICMP_PORT_UNREACH_CODE;
    hdr->icmp_ident = 0; // unused, must be zero
    hdr->icmp_seq_nb = 0; // unused, must be zero
    hdr->icmp_cksum = 0;

    // 获取原始 IP 头和数据(至少前 8 字节)
    struct rte_ipv4_hdr* orig_ipv4_hdr = rte_pktmbuf_mtod(orig_mbuf, struct rte_ipv4_hdr *);
    int orig_ip_hdr_len = rte_ipv4_hdr_len(orig_ipv4_hdr);
    int orig_data_len = rte_pktmbuf_data_len(orig_mbuf);
    // 计算ICMP负载数据长度，需要包含原始 IP 头 + 原始数据的前 8 字节
    // 如果原始数据长度不足8字节，则包含全部数据
    int copy_len = orig_data_len > (orig_ip_hdr_len + 8) ? (orig_ip_hdr_len + 8) : orig_data_len;

    u8* payload = (u8*)rte_pktmbuf_append(m, copy_len);
    rte_memcpy(payload, orig_ipv4_hdr, copy_len);

    // 计算校验和
    hdr->icmp_cksum = checksum((u16*)hdr, ICMP_HDR_LEN + copy_len, 0);

    u32 dst_ip = orig_ipv4_hdr->src_addr;
    ipv4_send_mbuf(m, IPPROTO_ICMP, dst_ip);
}
