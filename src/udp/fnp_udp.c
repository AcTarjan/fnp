#include "fnp_udp.h"

#include <fnp_common.h>
#include <fnp_ipv4.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <arpa/inet.h>

#define FNP_UDP_HDR_LEN 8
#define MAX_PORT_NUM    8


udp_sock_t* udp_sock_ipv4(ipv4_5tuple_t* key)
{
    udp_sock_t* sk = (udp_sock_t*)rte_malloc(NULL, sizeof(udp_sock_t), 0);
    if (sk == NULL)
    {
        return NULL;
    }

    return sk;
}

void udp_sock_free(udp_sock_t* sk)
{
    rte_free(sk);
}

void udp_recv_mbuf(struct rte_mbuf* m)
{
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    sock_t* sock = get_sock_from_hash(ip_hdr);
    if (sock == NULL)
    {
        FNP_WARN("fail to find udp sock")
        rte_pktmbuf_free(m);
        return;
    }

    u16 iphdr_len = rte_ipv4_hdr_len(ip_hdr);
    struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr* )rte_pktmbuf_adj(m, iphdr_len);        //去掉ipv4
    rte_pktmbuf_adj(m, FNP_UDP_HDR_LEN);      //去掉udp头

    int data_len = rte_pktmbuf_data_len(m);
    int udp_data_len = rte_cpu_to_be_16(udp_hdr->dgram_len) - FNP_UDP_HDR_LEN;
    rte_pktmbuf_trim(m, data_len - udp_data_len);      //去掉以太网帧填充的数据

    sockinfo_t* info = sockinfo(m);
    info->rip = ip_hdr->src_addr;
    info->rport = udp_hdr->src_port;


    if (rte_ring_enqueue(sock->rx, m) != 0)
    {
        //入队失败,释放mbuf
        rte_pktmbuf_free(m);
    }

}

void udp_send_mbuf(struct rte_mbuf* m)
{
    struct rte_udp_hdr* hdr = (struct rte_udp_hdr*) rte_pktmbuf_prepend(m, FNP_UDP_HDR_LEN);
    sockinfo_t* info = sockinfo(m);
    hdr->src_port = info->lport;
    hdr->dst_port = info->rport;
    hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len);
    hdr->dgram_cksum = 0;

    ipv4_send_mbuf(m, IPPROTO_UDP, info->rip);
}
