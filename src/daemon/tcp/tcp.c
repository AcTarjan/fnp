#include "tcp.h"
#include "tcp_comm.h"
#include "tcp_sock.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "ipv4.h"
#include "fnp_context.h"

#include <rte_ip.h>
#include <rte_tcp.h>

static tcp_recv_func tcp_recv[TCP_STATE_END];
static tcp_send_func tcp_send[TCP_STATE_END];

void init_tcp_layer()
{
    tcp_recv[TCP_CLOSED] = tcp_closed_recv;
    tcp_recv[TCP_LISTEN] = tcp_listen_recv;
    tcp_recv[TCP_SYN_SENT] = tcp_synsent_recv;
    tcp_recv[TCP_SYN_RECV] = tcp_synrecv_recv;
    tcp_recv[TCP_ESTABLISHED] = tcp_estab_recv;
    tcp_recv[TCP_CLOSE_WAIT] = tcp_estab_recv;
    tcp_recv[TCP_LAST_ACK] = tcp_estab_recv;
    tcp_recv[TCP_FIN_WAIT_1] = tcp_estab_recv;
    tcp_recv[TCP_FIN_WAIT_2] = tcp_estab_recv;
    tcp_recv[TCP_CLOSING] = tcp_estab_recv;
    tcp_recv[TCP_TIME_WAIT] = tcp_estab_recv;

    tcp_send[TCP_CLOSED] = tcp_closed_send;
    tcp_send[TCP_LISTEN] = tcp_listen_send;
    tcp_send[TCP_SYN_SENT] = tcp_syn_send;
    tcp_send[TCP_SYN_RECV] = tcp_syn_send;
    tcp_send[TCP_ESTABLISHED] = tcp_data_send;
    tcp_send[TCP_CLOSE_WAIT] = tcp_data_send;
    tcp_send[TCP_LAST_ACK] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_1] = tcp_data_send;
    tcp_send[TCP_FIN_WAIT_2] = tcp_data_send;
    tcp_send[TCP_CLOSING] = tcp_data_send;
    tcp_send[TCP_TIME_WAIT] = tcp_data_send;
}

static inline void tcp_decode_option(tcp_option *opt, u8 *bytes, u8 len)
{
    opt->mss = 0;
    opt->wnd_scale = 255; //  不能为0, 用来区分没有窗口扩展和窗口扩展为0
    opt->permit_sack = false;

    u8 index = 0;
    while (index < len)
    {
        switch (bytes[index])
        {
        case 0: // EOL
            return;
        case 1:
        { // NOP
            index++;
            break;
        }
        case 2:
        { // MSS
            u16 *mss = bytes + index + 2;
            opt->mss = fnp_swap16(*mss);
            index += 4;
            break;
        }
        case 3:
        { // Window Scale
            opt->wnd_scale = bytes[index + 2];
            index += 3;
            break;
        }
        case 4:
        {
            opt->permit_sack = true;
            index += 2;
            break;
        }
        default:
        {
            u8 olen = bytes[index + 1];
            index += olen;
        }
        }
    }
}

static inline void tcp_seg_init(struct rte_mbuf *m, tcp_segment *seg)
{
    struct rte_ipv4_hdr *ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u8 ipv4_hdr_len = rte_ipv4_hdr_len(ipv4Hdr);
    struct rte_tcp_hdr *tcpHdr = (struct rte_tcp_hdr *)rte_pktmbuf_adj(m, ipv4_hdr_len);

    seg->iface_id = m->port;
    seg->proto = IPPROTO_TCP;
    seg->rip = ipv4Hdr->src_addr;
    seg->lip = ipv4Hdr->dst_addr;
    seg->rport = tcpHdr->src_port;
    seg->lport = tcpHdr->dst_port;
    seg->flags = tcpHdr->tcp_flags;
    seg->hdr_len = tcpHdr->data_off >> 2;
    seg->seq = fnp_swap32(tcpHdr->sent_seq);
    seg->ack = fnp_swap32(tcpHdr->recv_ack);
    seg->rx_win = fnp_swap16(tcpHdr->rx_win);
    seg->data_len = fnp_swap16(ipv4Hdr->total_length) - ipv4_hdr_len - seg->hdr_len;

    if (seg_has_opt(seg))
    {
        u8 *opt_bytes = rte_pktmbuf_mtod_offset(m, u8 *, TCP_HDR_MIN_LEN);
        tcp_decode_option(&seg->opt, opt_bytes, seg->hdr_len - TCP_HDR_MIN_LEN);
    }

    rte_pktmbuf_adj(m, seg->hdr_len);

    // 修改为实际的数据长度，mbuf的data_len可能会因为填充一些字节来满足最小以太网帧64字节的长度导致data_len偏大。
    // 比如实际TCP数据4字节，TCP头20字节，IP头20字节，以太网头14字节，一共62字节，mbuf会在末尾填充2字节，满足64字节要求。
    // 导致mbuf的data_len和pkt_len都是6字节，而实际TCP数据只有4字节。
    i32 pkt_len = rte_pktmbuf_pkt_len(m);
    if (pkt_len > seg->data_len)
        rte_pktmbuf_trim(m, pkt_len - seg->data_len); // 去掉填充的字节
    seg->data = m;
}

// 可以将连接置为CLOSED状态, 但不能tcp_free_sock释放资源, 由用户调用tcp_free_sock释放资源
void tcp_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);

    tcp_segment seg;
    tcp_seg_init(m, &seg);
    i32 state = TCP_CLOSED;
    tcp_sock_t *sock = NULL;

    fsocket_t *socket = get_socket_from_hash(ipv4Hdr);
    if (likely(socket != NULL))
    {
        sock = socket;
        state = tcp_get_state(sock);
    }

    // mbuf在tcp_recv中释放, 释放mbuf不影响seg
    tcp_recv[state](sock, &seg);
}

static inline void tcp_handle_user_req(fsocket_t *socket)
{
    tcp_sock_t *sock = socket;

    switch (socket->user_req)
    {
    case FNP_CONNECT_REQ:
    {
        socket->user_req = 0;
        tcp_set_state(sock, TCP_SYN_SENT);
        break;
    }
    case FNP_CLOSE_REQ:
    {
        socket->user_req = 0;
        if (tcp_get_state(sock) == TCP_CLOSE_WAIT)
            tcp_set_state(sock, TCP_LAST_ACK);
        else
            tcp_set_state(sock, TCP_FIN_WAIT_1);
        break;
    }
    }
}

void tcp_recv_from_app(fsocket_t *socket)
{
    struct rte_mbuf *mbufs[64];
    tcp_sock_t *sock = socket;
    // 从应用层接收数据，放到缓存中
    if (tcp_get_state(sock) != TCP_LISTEN)
    {
        i32 avail = FNP_MIN(fnp_pring_avail(sock->txbuf), 64);
        u32 num = rte_ring_dequeue_burst(socket->tx, mbufs, avail, NULL);
        if (num > 0)
        {
            // mbuf融合，送进发送队列
            // printf("recv %d mbufs from app\n", num);
            fnp_pring_enqueue_bulk(sock->txbuf, mbufs, num);
        }
    }

    // 处理用户请求
    tcp_handle_user_req(socket);

    // 发送缓存中的TCP数据
    i32 state = tcp_get_state(sock);
    tcp_send[state](sock);
}
