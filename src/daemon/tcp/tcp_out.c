#include "fnp_worker.h"
#include "tcp_out.h"
#include "tcp_sock.h"
#include "tcp_comm.h"
#include "ipv4.h"
#include "fnp_ring.h"

#include <rte_tcp.h>

#include "tcp_timer.h"

typedef void (*tcp_send_func)(tcp_sock_t* sk);
static tcp_send_func tcp_send_handler[TCP_STATE_END];


static u8 tcp_outflags[TCP_STATE_END] = {
    RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG,
    0,
    RTE_TCP_SYN_FLAG,
    RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG,
    RTE_TCP_ACK_FLAG,
    RTE_TCP_ACK_FLAG,
    RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG,
    RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG,
    RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG,
    RTE_TCP_ACK_FLAG,
    RTE_TCP_ACK_FLAG,
    RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG,
};

#define TCP_SYN_OPTION_HDR_LEN  8

static inline void tcp_write_syn_options(tcp_sock_t* sock, struct rte_tcp_hdr* hdr)
{
    u8* optStart = (u8*)(hdr + 1);
    u8 i = 0;

    // Maximum Segment Size Option
    optStart[i] = 2;
    optStart[i + 1] = 4;
    u16* mss = optStart + i + 2;
    *mss = fnp_swap16(sock->mss);
    i += 4;

    // Window Scale option, shift count = 7
    optStart[i] = 3;
    optStart[i + 1] = 3;
    optStart[i + 2] = sock->rcv_wnd_scale;
    i += 3;

    // NOP Option填充
    optStart[i] = 1;
    i++;

    // SACK Permitted Option
    // optStart[i] = 4;
    // optStart[i + 1] = 2;
    // i += 2;

    // End of Option List Option
    while (i % 4 != 0)
    {
        optStart[i] = 0;
        i++;
    }
}

static void tcp_send_mbuf(tcp_sock_t* sock, struct rte_mbuf* m, u32 seq, u8 flags)
{
    fsocket_t* socket = fsocket(sock);
    sock->rcv_wnd = fnp_ring_free_count(socket->rx) * sock->mss;
    u8 hdr_len = TCP_HDR_MIN_LEN;
    if (unlikely(flags & RTE_TCP_SYN_FLAG))
    {
        hdr_len += TCP_SYN_OPTION_HDR_LEN;
    }

    struct rte_tcp_hdr* hdr = (struct rte_tcp_hdr*)rte_pktmbuf_prepend(m, hdr_len);

    hdr->src_port = fsocket_local_addr_const(socket)->port;
    hdr->dst_port = fsocket_remote_addr_const(socket)->port;
    hdr->sent_seq = fnp_swap32(seq);
    hdr->recv_ack = fnp_swap32(sock->rcv_nxt);
    hdr->tcp_flags = flags;
    hdr->rx_win = fnp_swap16(sock->rcv_wnd >> sock->rcv_wnd_scale);
    hdr->tcp_urp = fnp_swap16(sock->snd_up);
    hdr->data_off = ((hdr_len >> 2) << 4); // 头部长度/4，再左移4位
    hdr->cksum = 0;

    if (unlikely(flags & RTE_TCP_SYN_FLAG))
    {
        tcp_write_syn_options(sock, hdr);
    }

    ipv4_send_mbuf(m, IPPROTO_TCP, fsocket_remote_addr_const(socket)->ip);
}

void tcp_send_rst(tcp_segment* seg)
{
    struct rte_mbuf* m = alloc_mbuf();
    if (unlikely(m == NULL))
        return;

    struct rte_tcp_hdr* hdr = (struct rte_tcp_hdr*)rte_pktmbuf_prepend(m, TCP_HDR_MIN_LEN);
    hdr->src_port = seg->local.port;
    hdr->dst_port = seg->remote.port;
    hdr->tcp_flags = RTE_TCP_RST_FLAG;
    hdr->data_off = 0x50;
    hdr->rx_win = 0;
    hdr->cksum = 0;
    hdr->tcp_urp = 0;
    if (seg->flags & RTE_TCP_ACK_FLAG)
    {
        hdr->sent_seq = fnp_swap32(seg->ack);
    }
    else
    {
        hdr->tcp_flags |= RTE_TCP_ACK_FLAG;
        hdr->sent_seq = 0;
        u32 recv_ack = seg->seq + seg->data_len;
        if (seg->flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
            recv_ack += 1;
        hdr->recv_ack = fnp_swap32(recv_ack);
    }

    ipv4_send_mbuf(m, IPPROTO_TCP, seg->remote.ip);
}

void tcp_send_ack(tcp_sock_t* sock, bool delay)
{
    if (likely(delay))
    {
        tcp_start_ack_timer(sock);
        return;
    }

    struct rte_mbuf* m = alloc_mbuf();
    if (unlikely(m == NULL))
    {
        printf("tcp_send_ack can't alloc mbuf!!!\n");
        return;
    }
    tcp_send_mbuf(sock, m, sock->snd_nxt, RTE_TCP_ACK_FLAG);
}

static inline bool tcp_allow_send(tcp_sock_t* sock, u32 seq, i32 len)
{
    i32 snd_len = seq - sock->snd_una;
    // i32 wnd = FNP_MIN(sock->adv_wnd << sock->snd_wnd_scale, sock->cc_algo.cwin * sock->mss);
    i32 wnd = sock->adv_wnd << sock->snd_wnd_scale;

    return (snd_len + len <= wnd);
}

void tcp_start_retransmit(tcp_sock_t* sock)
{
    fnp_list_node_t* last_node = fnp_list_last(&sock->pending_list);
    if (unlikely(last_node == NULL))
    {
        return;
    }

    tcp_mbufinfo_t* last_info = node_to_tcp_mbufinfo(last_node);
    sock->retransmitting_seq = last_info->seq;
    sock->is_retransmitting = 1;
}

void tcp_ack_pending_list(tcp_sock_t* sock, u32 ack)
{
    fnp_list_node_t* node = fnp_list_first(&sock->pending_list);
    while (node != NULL)
    {
        // 进入重传
        tcp_mbufinfo_t* info = node_to_tcp_mbufinfo(node);

        u32 seq = info->seq;
        u32 end_seq = seq + info->len; //[seq, end_seq)

        // ack < end_seq, 存在部分字节未确认
        if (SEQ_LT(ack, end_seq))
        {
            break;
        }

        fnp_list_node_t* next = node->next;

        fnp_list_delete(&sock->pending_list, node);
        free_mbuf(node->value); // 释放mbuf

        node = next;
    }
}

// 重传的数据包
static inline void tcp_retransmit_needed_packet(tcp_sock_t* sock)
{
    fnp_list_node_t* node = fnp_list_first(&sock->pending_list);
    while (node != NULL)
    {
        // 进入重传
        tcp_mbufinfo_t* info = node_to_tcp_mbufinfo(node);
        if (!tcp_allow_send(sock, info->seq, info->len))
            return;

        struct rte_mbuf* m = node->value;
        struct rte_mbuf* new_mbuf = clone_mbuf(m); // 浅克隆，间接引用，没有数据拷贝
        tcp_send_mbuf(sock, new_mbuf, info->seq, info->flags);

        // 不需要重新插入到队尾了
        if (info->seq == sock->retransmitting_seq)
        {
            sock->is_retransmitting = 0; // 重传完成
            return;
        }

        node = node->next;
    }
}

static inline void tcp_retransmit_packet_if_need(tcp_sock_t* sock)
{
    // 判断是否正在重传中
    if (unlikely(sock->is_retransmitting))
    {
        tcp_retransmit_needed_packet(sock);
        return;
    }
}

void tcp_send_syn(tcp_sock_t* sock)
{
    tcp_start_retransmit_timer(sock);

    struct rte_mbuf* m = alloc_mbuf();
    if (unlikely(m == NULL))
    {
        return;
    }

    u8 flags = tcp_outflags[tcp_get_state(sock)];
    tcp_send_mbuf(sock, m, sock->iss, flags);
    sock->snd_nxt = sock->iss + 1; // SYN包的序列号增加1
}

static void tcp_send_data(tcp_sock_t* sock, struct rte_mbuf* m)
{
    // 判断是否可以发送数据, 如果不可以启动一个事件
    // if (!tcp_allow_send(sock, sock->snd_nxt, sock->mss))
    //     return;
    tcp_start_retransmit_timer(sock);

    tcp_mbufinfo_t* info = get_tcp_mbufinfo(m);

    info->seq = sock->snd_nxt; // 记录发送序列号
    info->len = rte_pktmbuf_data_len(m);
    info->flags = tcp_outflags[tcp_get_state(sock)];

    // 将mbuf插入到待确认列表
    fnp_list_insert_tail(&sock->pending_list, &info->node, m);

    struct rte_mbuf* new_mbuf = clone_mbuf(m);
    if (unlikely(new_mbuf == NULL))
    {
        // 暂存到待发送队列中
        return;
    }
    tcp_send_mbuf(sock, new_mbuf, info->seq, info->flags);
    sock->snd_nxt += info->len;

    // 停止dealy ack定时器
    tcp_stop_ack_timer(sock);
}

static void tcp_data_send(tcp_sock_t* sock)
{
    fsocket_t* socket = fsocket(sock);
    static struct rte_mbuf* mbufs[32];
    u32 n = fnp_ring_dequeue_burst(socket->tx, mbufs, 32);
    for (int i = 0; i < n; i++)
    {
        tcp_send_data(sock, mbufs[i]);
    }

    // 如果还有数据发送, 则继续唤醒socket
    if (fnp_ring_count(socket->tx) > 0)
    {
        fsocket_notify_backend(socket);
        return;
    }

    // 当走到这说明所有数据已经发送完毕，检查一下是否需要关闭
    if (unlikely(socket->close_requested))
    {
        // 发送FIN数据包
        if (tcp_get_state(sock) == TCP_ESTABLISHED)
            tcp_set_state(sock, TCP_FIN_WAIT_1);
        else if (tcp_get_state(sock) == TCP_CLOSE_WAIT)
            tcp_set_state(sock, TCP_LAST_ACK);
    }
}

void tcp_send_fin(tcp_sock_t* sock)
{
    tcp_start_retransmit_timer(sock);

    struct rte_mbuf* m = alloc_mbuf();
    if (unlikely(m == NULL))
    {
        return;
    }

    tcp_mbufinfo_t* info = get_tcp_mbufinfo(m);
    info->seq = sock->snd_nxt; // 记录发送序列号
    info->len = 0;
    info->flags = tcp_outflags[tcp_get_state(sock)];
    sock->fin_sent = 1; // 标记已经发送FIN

    sock->snd_nxt += 1; // 更新发送序列号
    // 将mbuf插入到待确认列表
    fnp_list_insert_tail(&sock->pending_list, &info->node, m);

    struct rte_mbuf* new_mbuf = clone_mbuf(m);
    if (unlikely(new_mbuf == NULL))
    {
        printf("tcp_send_fin clone mbuf failed\n");
        return;
    }
    tcp_send_mbuf(sock, new_mbuf, info->seq, info->flags);

    // 停止dealy ack定时器
    tcp_stop_ack_timer(sock);
}


static void tcp_new_send(tcp_sock_t* sock)
{
    fsocket_t* socket = fsocket(sock);
    if (unlikely(socket->close_requested))
    {
        tcp_set_state(sock, TCP_CLOSED);
        return;
    }

    if (likely(socket->request_syn))
    {
        tcp_set_state(sock, TCP_SYN_SENT);
    }
}

static void tcp_empty_send(tcp_sock_t* sock)
{
    fsocket_t* socket = fsocket(sock);
    if (unlikely(socket->close_requested))
    {
        tcp_set_state(sock, TCP_CLOSED);
    }
}

void tcp_send_init()
{
    tcp_send_handler[TCP_NEW] = tcp_new_send; // 等待connect和close
    tcp_send_handler[TCP_LISTEN] = tcp_empty_send;
    tcp_send_handler[TCP_SYN_SENT] = tcp_empty_send;
    tcp_send_handler[TCP_SYN_RECV] = tcp_empty_send;
    tcp_send_handler[TCP_ESTABLISHED] = tcp_data_send; //等待close
    tcp_send_handler[TCP_CLOSE_WAIT] = tcp_data_send;
    tcp_send_handler[TCP_LAST_ACK] = tcp_empty_send;
    tcp_send_handler[TCP_FIN_WAIT_1] = tcp_empty_send;
    tcp_send_handler[TCP_FIN_WAIT_2] = tcp_empty_send;
    tcp_send_handler[TCP_CLOSING] = tcp_empty_send; // 等待close
    tcp_send_handler[TCP_TIME_WAIT] = tcp_empty_send; // 等待close
    tcp_send_handler[TCP_CLOSED] = tcp_empty_send; // 等待close
}

void tcp_send(tcp_sock_t* sock)
{
    // 发送缓存中的TCP数据
    i32 state = tcp_get_state(sock);
    tcp_send_handler[state](sock);
}
