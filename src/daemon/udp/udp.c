#include "udp.h"

#include "fnp_common.h"
#include "fnp_worker.h"
#include "ipv4.h"

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_jhash.h>


#define FNP_UDP_HDR_LEN 8
#define MAX_PORT_NUM 8


static void udp_handler(fsocket_t* socket)
{
    // 处理用户请求
    if (socket->request_close)
    {
        // 把应用层待发送的数据发送完成
        if (fnp_pring_empty(socket->tx))
        {
            free_fsocket(socket);
            return;
        }
    }

    static struct rte_mbuf* mbufs[SOCKET_TX_BURST_NUM];

    // 从应用层接收数据，发送出去。
    const u32 num = fnp_pring_dequeue_burst(socket->tx, mbufs, SOCKET_TX_BURST_NUM);
    for (i32 i = 0; i < num; i++)
    {
        udp_send_mbuf(socket, mbufs[i]);
    }
}

udp_sock_t* udp_create_sock(fsockaddr_t* local, fsockaddr_t* remote)
{
    udp_sock_t* sock = fnp_zmalloc(sizeof(udp_sock_t));
    if (sock == NULL)
    {
        return NULL;
    }

    fsocket_t* socket = fsocket(sock);

    socket->handler = udp_handler;

    return sock;
}


void free_udp_sock(udp_sock_t* sock)
{
    fnp_free(sock);
}


void udp_send_mbuf(fsocket_t* socket, struct rte_mbuf* m)
{
    fmbuf_info_t* info = get_fmbuf_info(m);

    // 检查对方是否是本地Socket
    if (lookup_iface(info->remote.ip) != NULL)
    {
        fsocket_t* rsocket = lookup_socket_table(socket->proto, &info->remote, &socket->local);
        if (rsocket == NULL)
        {
            rsocket = lookup_socket_table(socket->proto, &info->remote, NULL);
        }

        if (rsocket != NULL)
        {
            if (!fnp_socket_enqueue_for_app(rsocket, m))
            {
                free_mbuf(m);
            }
        }
        else
        {
            free_mbuf(m);
        }

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

void udp_recv_from_net(struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    // 这个socket可能是udp_sock, 也可能是quic_sock
    fsocket_t* socket = lookup_socket_table_by_ipv4(ip_hdr);
    if (socket == NULL)
    {
        FNP_WARN("fail to find udp sock")
        free_mbuf(m);
        return;
    }

    u16 iphdr_len = rte_ipv4_hdr_len(ip_hdr);
    struct rte_udp_hdr* udp_hdr = (struct rte_udp_hdr*)rte_pktmbuf_adj(m, iphdr_len); // 去掉ipv4
    rte_pktmbuf_adj(m, FNP_UDP_HDR_LEN); // 去掉udp头

    int data_len = rte_pktmbuf_data_len(m);
    int udp_data_len = rte_cpu_to_be_16(udp_hdr->dgram_len) - FNP_UDP_HDR_LEN;
    rte_pktmbuf_trim(m, data_len - udp_data_len); // 去掉以太网帧填充的数据

    fmbuf_info_t* info = get_fmbuf_info(m);;
    info->remote.family = FSOCKADDR_IPV4;
    info->remote.ip = ip_hdr->src_addr;
    info->remote.port = udp_hdr->src_port;
    info->local.family = FSOCKADDR_IPV4;
    info->local.ip = ip_hdr->dst_addr;
    info->local.port = udp_hdr->dst_port;

    // 交付给应用层/QUIC处理
    if (!fnp_socket_enqueue_for_app(socket, m))
    {
        // 入队失败,释放mbuf
        free_mbuf(m);
    }
}
