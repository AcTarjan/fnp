#include "fnp_context.h"
#include "tcp_out.h"
#include "tcp_sock.h"
#include "tcp_comm.h"
#include "tcp_timer.h"
#include "ipv4.h"
#include "fnp_pring.h"

#include <rte_tcp.h>

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
};

void tcp_write_syn_options(tcp_sock_t *sock, struct rte_tcp_hdr *hdr)
{
    u8 *optStart = (u8 *)(hdr + 1);
    u8 i = 0;

    // Maximum Segment Size Option
    optStart[i] = 2;
    optStart[i + 1] = 4;
    u16 *mss = optStart + i + 2;
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
    optStart[i] = 4;
    optStart[i + 1] = 2;
    i += 2;

    // End of Option List Option
    while (i % 4 != 0)
    {
        optStart[i] = 0;
        i++;
    }
}

void tcp_send_syn_mbuf(tcp_sock_t *sock, struct rte_mbuf *m, u8 flags)
{
    fnp_socket_t *socket = fnp_socket(sock);
    sock->rcv_wnd = rte_ring_free_count(socket->rx) * sock->mss;
    sock->snd_nxt = sock->iss;

    u8 hdr_len = TCP_HDR_MIN_LEN + 8;

    struct rte_tcp_hdr *hdr = (struct rte_tcp_hdr *)rte_pktmbuf_prepend(m, hdr_len);
    hdr->src_port = socket->addr.lport;
    hdr->dst_port = socket->addr.rport;
    hdr->sent_seq = fnp_swap32(sock->snd_nxt);
    hdr->recv_ack = fnp_swap32(sock->rcv_nxt);
    hdr->tcp_flags = flags;
    hdr->rx_win = fnp_swap16(sock->rcv_wnd); // 此时不进行窗口缩放
    hdr->cksum = 0;
    hdr->tcp_urp = fnp_swap16(sock->snd_up);
    hdr->data_off = ((hdr_len) / 4) << 4;

    tcp_write_syn_options(sock, hdr);

    //    m->ol_flags |= struct rte_mbuf_F_TX_TCP_CKSUM;

    ipv4_fast_send_mbuf(socket, m);
}

void tcp_send_data_mbuf(tcp_sock_t *sock, struct rte_mbuf *m, u8 flags)
{
    fnp_socket_t *socket = fnp_socket(sock);
    sock->rcv_wnd = rte_ring_free_count(socket->rx) * sock->mss;
    u8 hdr_len = TCP_HDR_MIN_LEN;

    struct rte_tcp_hdr *hdr = (struct rte_tcp_hdr *)rte_pktmbuf_prepend(m, hdr_len);

    hdr->src_port = socket->addr.lport;
    hdr->dst_port = socket->addr.rport;
    hdr->sent_seq = fnp_swap32(sock->snd_nxt);
    hdr->recv_ack = fnp_swap32(sock->rcv_nxt);
    hdr->tcp_flags = flags;
    hdr->rx_win = fnp_swap16(sock->rcv_wnd >> sock->rcv_wnd_scale);
    hdr->cksum = 0;
    hdr->tcp_urp = fnp_swap16(sock->snd_up);
    hdr->data_off = ((hdr_len) / 4) << 4;

    //    m->ol_flags |= struct rte_mbuf_F_TX_TCP_CKSUM;

    ipv4_fast_send_mbuf(socket, m);
}

void tcp_send_rst(tcp_segment *seg)
{
    struct rte_mbuf *m = alloc_mbuf();

    struct rte_tcp_hdr *hdr = (struct rte_tcp_hdr *)rte_pktmbuf_prepend(m, TCP_HDR_MIN_LEN);
    hdr->src_port = seg->lport;
    hdr->dst_port = seg->rport;
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

    //    m->ol_flags |= struct rte_mbuf_F_TX_TCP_CKSUM;

    ipv4_send_mbuf(m, IPPROTO_TCP, seg->rip);
}

void tcp_send_ack(tcp_sock_t *sk, bool delay)
{
    static i64 count_ack = 0;
    if (likely(delay))
    {
        if (tcp_timer_is_running(sk, TCPT_DELAY_ACK))
            return;
        tcp_timer_start(sk, TCPT_DELAY_ACK);
    }
    else
    {
        struct rte_mbuf *m = alloc_mbuf();
        if (m == NULL)
        {
            printf("tcp_send_ack can't alloc mbuf!!!\n");
            return;
        }
        tcp_send_data_mbuf(sk, m, RTE_TCP_ACK_FLAG);
    }
}

// send SYN or SYN|ACK
void tcp_syn_send(tcp_sock_t *sk)
{
    if (sk->snd_nxt == sk->snd_una)
    { // 还未发送过SYN
        struct rte_mbuf *m = alloc_mbuf();
        if (m == NULL)
        {
            printf("tcp_syn_send fail to alloc mbuf\n");
            return;
        }
        tcp_send_syn_mbuf(sk, m, tcp_outflags[tcp_get_state(sk)]);
        sk->snd_nxt += 1;
        if (SEQ_LT(sk->snd_max, sk->snd_nxt))
            sk->snd_max = sk->snd_nxt;

        // 启动重传定时器
        tcp_timer_start(sk, TCPT_REXMT);
    }
}

// send FIN|ACK
void tcp_fin_send(tcp_sock_t *sock)
{
}

// send tcp segment
void tcp_data_send(tcp_sock_t *sk)
{
    // sk->snd_wnd = FNP_MIN(sk->adv_wnd << sk->snd_wnd_scale, sk->cwnd);
    sk->snd_wnd = sk->adv_wnd << sk->snd_wnd_scale; // 先不进行拥塞控制
    while (1)
    {
        // 从还没发送过的数据开始发送，snd_una为窗口下界。
        // 当重传时，只需要让 snd_nxt = snd_una
        i32 snd_len = sk->snd_nxt - sk->snd_una;
        // 发送窗口内的数据都已经发送完了
        if (snd_len >= sk->snd_wnd)
        {
            break;
        }

        u8 flags = tcp_outflags[tcp_get_state(sk)];
        struct rte_mbuf *m = fnp_pring_top(sk->txbuf, sk->tx_offset);
        struct rte_mbuf *m2 = NULL; // 实际发送的mbuf
        i32 data_len = 0;           // 实际发送的数据长度
        if (unlikely(m != NULL))    // 有应用层数据要发送
        {
            data_len = rte_pktmbuf_data_len(m);

            // clone一份发送出去, 浅克隆：间接引用，没有数据拷贝
            m2 = clone_mbuf(m);
            if (m2 == NULL)
            {
                printf("tcp_data_send clone mbuf failed\n");
                return;
            }
            sk->tx_offset++;

            if (flags & RTE_TCP_FIN_FLAG)
            {
                struct rte_mbuf *next = fnp_pring_top(sk->txbuf, sk->tx_offset);
                if (next != NULL) // 如果不是最后一个包，不能携带FIN
                    flags &= ~RTE_TCP_FIN_FLAG;
            }
        }
        else
        {
            // 没有应用层数据要发送，但有FIN要发送
            if (unlikely((flags & RTE_TCP_FIN_FLAG) && !sk->fin_sent)) // 判断是否已经发送过FIN
            {
                // 分配一个空的mbuf
                sk->fin_sent = 1;
                m2 = alloc_mbuf();
                if (m2 == NULL)
                {
                    printf("fnp_mbuf_alloc failed to send fin\n");
                    return;
                }
            }
            else
            {
                break;
            }
        }

        // 发送出去
        tcp_send_data_mbuf(sk, m2, flags);

        sk->snd_nxt += data_len;
        sk->snd_nxt += (flags & RTE_TCP_FIN_FLAG);
        if (SEQ_LT(sk->snd_max, sk->snd_nxt))
            sk->snd_max = sk->snd_nxt;

        // 如果重传定时器没有启动，则启动它
        if (unlikely(!tcp_timer_is_running(sk, TCPT_REXMT)))
        {
            tcp_timer_start(sk, TCPT_REXMT);
        }

        // 如果延迟ACK启动了，则停止它
        if (tcp_timer_is_running(sk, TCPT_DELAY_ACK))
        {
            tcp_timer_stop(sk, TCPT_DELAY_ACK);
        }
    }
}

void tcp_listen_send(tcp_sock_t *sock) {}

void tcp_closed_send(tcp_sock_t *sock)
{
    fnp_socket_t *socket = fnp_socket(sock);
    if (socket->can_free)
        free_socket(socket);
}
