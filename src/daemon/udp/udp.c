#include "udp.h"

#include "fnp_common.h"
#include "fnp_worker.h"
#include "fnp_iface.h"
#include "ipv4.h"
#include "icmp.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_jhash.h>

#define FNP_UDP_HDR_LEN 8

void free_udp_sock(udp_sock_t* sock)
{
    fnp_free(sock);
}

// 本地转发路径
// 只有目的地址不确定的UDP Socket需要，检查对方是否是本地
// TCP Socket的四元组确定，可以在创建Socket时检查是否是本地直接通信
static inline void local_forward_path(fsockaddr_t* local, fsockaddr_t* remote, struct rte_mbuf* m)
{
    fsocket_t* dst_socket = lookup_socket_table(fnp_protocol_udp, remote, local);
    if (dst_socket == NULL)
    {
        dst_socket = lookup_socket_table(fnp_protocol_udp, remote, NULL);
    }

    if (unlikely(dst_socket == NULL))
    {
        free_mbuf(m);
        return;
    }

    if (unlikely(!fsocket_enqueue_for_app(dst_socket, m)))
    {
        static int fail_count = 0;
        fail_count++;
        printf("enqueue failed %d\n", fail_count);
        free_mbuf(m);
    }
}

void udp_send_mbuf(fsocket_t* socket, struct rte_mbuf* m)
{
    fmbuf_info_t* info = get_fmbuf_info(m);
    // 检查是否是local forward path
    if (is_local_ipaddr(info->remote.ip))
    {
        local_forward_path(&info->local, &info->remote, m);
        return;
    }

    // 目的地址不是本地的, 直接发送到网络上
    struct rte_udp_hdr* hdr = (struct rte_udp_hdr*)rte_pktmbuf_prepend(m, FNP_UDP_HDR_LEN);
    hdr->src_port = socket->local.port;
    hdr->dst_port = info->remote.port;
    hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len);
    hdr->dgram_cksum = 0;

    ipv4_send_mbuf(m, IPPROTO_UDP, info->remote.ip);
}

void udp_handle_fsocket_event(fsocket_t* socket, u64 event)
{
    // 判断是否有应用数据
#define UDP_BURST_SIZE 32
    static struct rte_mbuf* mbufs[UDP_BURST_SIZE];

    u32 n = fnp_ring_dequeue_burst(socket->tx, (void**)mbufs, UDP_BURST_SIZE);
    for (int i = 0; i < n; i++)
    {
        udp_send_mbuf(socket, mbufs[i]);
    }

    // 可能还有数据发送, 则继续唤醒socket
    if (n == UDP_BURST_SIZE)
    {
        fsocket_notify_backend(socket);
    }
}

// 处理来自IP层的UDP数据包
static inline void udp_recv_mbuf(fsocket_t* socket, struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u16 iphdr_len = rte_ipv4_hdr_len(ip_hdr);
    struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)rte_pktmbuf_adj(m, iphdr_len); // 去掉ipv4
    rte_pktmbuf_adj(m, FNP_UDP_HDR_LEN); // 去掉udp头

    int data_len = rte_pktmbuf_data_len(m);
    int udp_data_len = rte_cpu_to_be_16(udp_hdr->dgram_len) - FNP_UDP_HDR_LEN;
    rte_pktmbuf_trim(m, data_len - udp_data_len); // 去掉以太网帧填充的数据

    fmbuf_info_t* info = get_fmbuf_info(m);
    info->remote.family = FSOCKADDR_IPV4;
    info->remote.ip = ip_hdr->src_addr;
    info->remote.port = udp_hdr->src_port;
    info->local.family = FSOCKADDR_IPV4;
    info->local.ip = ip_hdr->dst_addr;
    info->local.port = udp_hdr->dst_port;

    // 交付给应用层/QUIC处理
    if (unlikely(fsocket_enqueue_for_app(socket, m) == false))
    {
        free_mbuf(m);
    }
}

void udp_recv_mbuf_from_ipv4(struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);

    // 查找匹配的Socket
    fsocket_t* socket = lookup_socket_table_by_ipv4(hdr);
    if (unlikely(socket == NULL))
    {
        icmp_send_port_unreachable(m);
        free_mbuf(m);
        return;
    }

    udp_recv_mbuf(socket, m);
}

udp_sock_t* udp_create_sock(fsockaddr_t* local, fsockaddr_t* remote)
{
    udp_sock_t* sock = fnp_zmalloc(sizeof(udp_sock_t));
    if (sock == NULL)
    {
        return NULL;
    }

    return sock;
}
