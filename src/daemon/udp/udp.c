#include "udp.h"

#include "fnp_common.h"
#include "fnp_context.h"
#include "ipv4.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_jhash.h>

#define FNP_UDP_HDR_LEN 8
#define MAX_PORT_NUM 8

void udp_send_mbuf(udp_sock_t *sock, struct rte_mbuf *m)
{
    fnp_socket_t *socket = fnp_socket(sock);
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, FNP_UDP_HDR_LEN);
    fnp_mbufinfo_t *info = fnp_mbufinfo(m);
    hdr->src_port = socket->lport;
    hdr->dst_port = info->addr.port;
    hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len);
    hdr->dgram_cksum = 0;

    ipv4_send_mbuf(m, IPPROTO_UDP, info->addr.ip);
}

void udp_fast_send_mbuf(udp_sock_t *sock, struct rte_mbuf *m)
{
    fnp_socket_t *socket = fnp_socket(sock);
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, FNP_UDP_HDR_LEN);
    hdr->src_port = socket->lport;
    hdr->dst_port = socket->rport;
    hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len);
    hdr->dgram_cksum = 0;

    ipv4_fast_send_mbuf(socket, m);
}

udp_sock_t *create_udp_sock()
{
    udp_sock_t *sock = fnp_zmalloc(sizeof(udp_sock_t));
    if (sock == NULL)
    {
        return NULL;
    }

    sock->send_func = udp_send_mbuf;

    return sock;
}

void free_udp_sock(udp_sock_t *sock)
{
    fnp_free(sock);
}

void udp_recv_from_net(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    fnp_socket_t *socket = get_socket_from_hash(ip_hdr);
    if (socket == NULL)
    {
        FNP_WARN("fail to find udp sock")
        free_mbuf(m);
        return;
    }

    u16 iphdr_len = rte_ipv4_hdr_len(ip_hdr);
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)rte_pktmbuf_adj(m, iphdr_len); // 去掉ipv4
    rte_pktmbuf_adj(m, FNP_UDP_HDR_LEN);                                               // 去掉udp头

    int data_len = rte_pktmbuf_data_len(m);
    int udp_data_len = rte_cpu_to_be_16(udp_hdr->dgram_len) - FNP_UDP_HDR_LEN;
    rte_pktmbuf_trim(m, data_len - udp_data_len); // 去掉以太网帧填充的数据

    fnp_mbufinfo_t *info = fnp_mbufinfo(m);
    info->addr.ip = ip_hdr->src_addr;
    info->addr.port = udp_hdr->src_port;

    if (rte_ring_enqueue(socket->rx, m) != 0)
    {
        // 入队失败,释放mbuf
        free_mbuf(m);
    }
}

void udp_recv_from_app(fnp_socket_t *socket)
{
    static struct rte_mbuf *mbufs[SOCKET_TX_BURST_NUM];
    udp_sock_t *sock = (udp_sock_t *)socket;

    // 从应用层接收数据，放到缓存中
    i32 num = rte_ring_dequeue_burst(socket->tx, mbufs, SOCKET_TX_BURST_NUM, NULL);
    for (i32 i = 0; i < num; i++)
    {
        sock->send_func(sock, mbufs[i]);
    }
}