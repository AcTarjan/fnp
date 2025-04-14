#include "fnp_context.h"
#include "tcp_sock.h"
#include "tcp_ofo.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_timer.h"

#include <unistd.h>
#include <rte_tcp.h>

static inline void tcp_handle_syn_option(tcp_sock_t *sk, tcp_segment *seg)
{
    if (seg_has_opt(seg))
    {
        if (unlikely(seg_set_syn(seg)))
        {
            if (seg->opt.mss != 0)
            { // 支持MSS选项
                sk->mss = FNP_MIN(sk->mss, seg->opt.mss);
            }

            // 支持
            if (seg->opt.wnd_scale != 255)
            { // 支持窗口扩展
                sk->snd_wnd_scale = seg->opt.wnd_scale;
            }
            else
            {
                sk->snd_wnd_scale = 0;
                sk->rcv_wnd_scale = 0;
            }

            sk->permit_sack = true;
        }
    }
}

// 所有字节都必须在接收窗口内, rcv_nxt <= seq < rcv_nxt + rcv_wnd
static inline bool acceptable_seq(tcp_sock_t *sk, tcp_segment *seg)
{
    if (unlikely(seg->data_len == 0))
        return SEQ_LE(sk->rcv_nxt, seg->seq) && SEQ_LT(seg->seq, sk->rcv_nxt + sk->rcv_wnd);

    const u32 end_seq = seg->seq + seg->data_len - 1;
    return SEQ_LE(sk->rcv_nxt, seg->seq) && SEQ_LT(end_seq, sk->rcv_nxt + sk->rcv_wnd);
}

static inline void tcp_handle_fin(tcp_sock_t *sock)
{
    fnp_socket_t *socket = fnp_socket(sock);
    u16 port = fnp_swap16(socket->rport);
    sock->rcv_nxt++; // FIN占用一个序列号
    printf("#####%d recv FIN!!!!! %u\n", port, sock->rcv_nxt - sock->irs);
    tcp_send_ack(sock, false);

    // 给应用层通知，不能接收了
    socket->can_recv = false;

    // 状态处理
    switch (sock->state)
    {
    case TCP_SYN_RECV:
    case TCP_ESTABLISHED:
    { //
        tcp_set_state(sock, TCP_CLOSE_WAIT);
        break;
    }
    case TCP_FIN_WAIT_1:
    {
        tcp_set_state(sock, TCP_CLOSING);
        break;
    }
    case TCP_FIN_WAIT_2:
    {
        tcp_set_state(sock, TCP_TIME_WAIT);
        tcp_timer_start(sock, TCPT_2MSL);
        break;
    }
    }
}

static inline void tcp_handle_in_order_data(tcp_sock_t *sock, tcp_segment *seg)
{
    fnp_socket_t *socket = &sock->socket;
    if (rte_ring_enqueue(socket->rx, seg->data) != 0)
    {
        FNP_WARN("can't enqueue tcp data!!!!!!\n");
        free_mbuf(seg->data);
        return;
    }
    sock->rcv_nxt += seg->data_len;

    // check out of order
    u8 flags = tcp_ofo_dequeue(sock);
    if (flags & RTE_TCP_FIN_FLAG)
        tcp_handle_fin(sock);
    tcp_send_ack(sock, true);
}

// 删除重传队列中的数据
static void ack_tcp_tx_buf(tcp_sock_t *sock, u32 ack)
{
    i32 ack_len = (i32)(ack - sock->snd_una);
    while (ack_len > 0)
    {
        struct rte_mbuf *m = fnp_pring_top(sock->txbuf, 0);
        if (m == NULL) // 注意：txbuf中不包括SYN和FIN，但是SYN和FIN占用1个seq，此时队列为空, 也pop不出来
            break;
        i32 data_len = rte_pktmbuf_data_len(m);
        if (data_len > ack_len)
        {

            rte_pktmbuf_adj(m, ack_len); // 去掉前ack_len
            break;
        }

        ack_len -= data_len;
        sock->tx_offset--;
        fnp_pring_dequeue(sock->txbuf, &m); // 从重传队列去掉
        rte_pktmbuf_free(m);                // 释放
    }
}

static inline void tcp_handle_ack(tcp_sock_t *sk, tcp_segment *seg)
{
    // RFC5961: snd_una - max_snd_wnd =< ack =< snd_max
    //  ack值必须满足上述要求
    if (SEQ_GT(sk->snd_una - sk->max_snd_wnd, seg->ack) || SEQ_GT(seg->ack, sk->snd_max))
    {
        tcp_send_ack(sk, false);
        return;
    }

    // snd_una < ack <= snd_max
    if (SEQ_LT(sk->snd_una, seg->ack) && SEQ_LE(seg->ack, sk->snd_max))
    {
        ack_tcp_tx_buf(sk, seg->ack);
        sk->dup_ack = 0;
        sk->snd_una = seg->ack;

        // 确认了所有已发送的字节
        if (sk->snd_una == sk->snd_max)
        {
            // printf("recv ack to stop retransmission timer\n");
            sk->cwnd = FNP_MIN(sk->cwnd << 1, TCP_MAX_CWND);
            tcp_timer_stop(sk, TCPT_REXMT);
        }
        else // 还有未确认的字节，重新计时
        {
            tcp_timer_start(sk, TCPT_REXMT);
        }
    }
    else if (seg->ack == sk->snd_una)
    {
        sk->dup_ack++;
        if (sk->dup_ack > 2)
        {
            sk->dup_ack = 0;
            sk->snd_nxt = sk->snd_una; // 立即重传
            //                printf("3 ack to stop retransmission timer\n");
            sk->cwnd = FNP_MIN(sk->cwnd, TCP_THRESHOLD);
            tcp_timer_stop(sk, TCPT_REXMT);
        }
    }
    else if (SEQ_GT(seg->ack, sk->snd_max)) // 确认了未发送的seq
    {
        tcp_send_ack(sk, false);
        return;
    }

    // snd.una =< ack =< snd.max, 更新发送窗口
    if (SEQ_LE(sk->snd_una, seg->ack) && SEQ_LE(seg->ack, sk->snd_max))
    {
        // The check here prevents using old segments to update the window.
        if (SEQ_LT(sk->snd_wl1, seg->seq) ||
            (sk->snd_wl1 == seg->seq && SEQ_LE(sk->snd_wl2, seg->ack)))
        {
            sk->adv_wnd = seg->rx_win;
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
        }
    }

    // 状态转换
    switch (tcp_get_state(sk))
    {
    case TCP_FIN_WAIT_1:
    {
        // 如果ack了自己发送的FIN, local->remote单向关闭已完成
        if (sk->snd_una == sk->snd_max)
        {
            tcp_set_state(sk, TCP_FIN_WAIT_2);
            // TODO: 向user调用返回ok
        }
        break;
    }
    case TCP_CLOSING:
    {
        // 自己已发送FIN，也收到了对端的FIN（回ACK了），现在又收到了对端对FIN的ACK
        if (sk->snd_una == sk->snd_max)
        {
            tcp_set_state(sk, TCP_TIME_WAIT);
            tcp_timer_start(sk, TCPT_2MSL);
        }
        break;
    }
    case TCP_LAST_ACK:
    {
        // 已收到FIN，并且自己也发送了FIN，这个ACK是对自己发送FIN的确认
        if (sk->snd_una == sk->snd_max)
        {
            tcp_set_state(sk, TCP_CLOSED);
        }
        break;
    }
    case TCP_TIME_WAIT:
    {
        // 之前发送的对FIN的ACK丢失
        tcp_send_ack(sk, false);
        tcp_timer_start(sk, TCPT_2MSL);
        break;
    }
    }
}

// 返回0继续处理FIN, 返回1表示收到乱序的数据包，稍后处理FIN
static inline void tcp_handle_data(tcp_sock_t *sk, tcp_segment *seg)
{
    // 收到顺序的包
    if (likely(sk->rcv_nxt == seg->seq))
    {
        tcp_handle_in_order_data(sk, seg);
        return;
    }

    // 乱序的数据包，先不处理FIN
    tcp_ofo_seg *ofo_seg = tcp_ofo_malloc(seg);
    seg->flags = 0; // 去掉FIN标记
    tcp_ofo_enqueue(&sk->ofo_root, ofo_seg);
    tcp_send_ack(sk, false); // 收到乱序的数据，立即回ACK
    return;
}

static void tcp_accept_conn(tcp_sock_t *sock)
{
    if (sock->parent != NULL)
    {
        tcp_sock_t *parent = sock->parent;
        fnp_socket_t *socket = &sock->socket;
        socket->can_free = false; // 不能释放, 会被用户空间接收
        if (rte_ring_enqueue(parent->socket.rx, socket) != 0)
        {
            FNP_WARN("can't enqueue socket!!!\n");
            free_socket(socket);
        }
    }
}

// 收到重传的SYN
// 收到SYN|ACK
// 收到ACK
// 收到数据包（可能乱序），对方已经是ESTABLISHED状态
void tcp_synrecv_recv(tcp_sock_t *sk, tcp_segment *seg)
{
    if (!acceptable_seq(sk, seg) && seg->seq != sk->irs)
    {
        free_mbuf(seg->data);
        if (!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return;
    }

    // check RST
    if (seg_set_rst(seg))
    {
        free_mbuf(seg->data);
        if (sk->rcv_nxt == seg->seq)
        {
            tcp_set_state(sk, TCP_CLOSED);
        }
        else
        { // rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    // check SYN
    if (seg_set_syn(seg))
    {
        free_mbuf(seg->data);
        if (seg->seq == sk->irs)
        {
            if (seg_set_ack(seg))
            { // recv SYN|ACK for our SYN, 适用于同时发送SYN
                if (seg->ack == sk->snd_max)
                {
                    sk->snd_una = seg->ack;
                    tcp_timer_stop(sk, TCPT_REXMT);
                    sk->adv_wnd = seg->rx_win;
                    sk->snd_wl1 = seg->seq;
                    sk->snd_wl2 = seg->ack;
                    tcp_handle_syn_option(sk, seg);
                    tcp_set_state(sk, TCP_ESTABLISHED);

                    tcp_accept_conn(sk);
                }
                else
                {
                    tcp_send_rst(seg);
                    return; // 不确定是否drop
                }
            }
            else
            { // recv retransmission syn
                tcp_handle_syn_option(sk, seg);
                tcp_timer_stop(sk, TCPT_REXMT);
                sk->snd_nxt = sk->snd_una; // 立即重传
            }
        }
        else
        { // recv a new syn again
            tcp_set_state(sk, TCP_CLOSED);
        }
        return;
    }

    if (seg_set_ack(seg))
    { // check ACK
        if (seg->ack == sk->snd_max)
        { // reach here only set ACK
            sk->snd_una = seg->ack;
            sk->adv_wnd = seg->rx_win;
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
            tcp_timer_stop(sk, TCPT_REXMT);
            tcp_set_state(sk, TCP_ESTABLISHED);

            tcp_accept_conn(sk);
            // 处理数据
            tcp_handle_data(sk, seg);
            return;
        }

        free_mbuf(seg->data);
        tcp_send_rst(seg);
    }
}

void tcp_listen_recv(tcp_sock_t *sk, tcp_segment *seg)
{
    // 直接释放
    free_mbuf(seg->data);

    // 检查RST
    if (seg_set_rst(seg))
    {
        return;
    }

    // 检查ACK, any ack is bad
    if (seg_set_ack(seg))
    {
        tcp_send_rst(seg);
        return;
    }

    // 检查SYN
    if (seg_set_syn(seg))
    {
        fnp_socket_t *new_socket = create_socket(&seg->addr, FNP_SO_REUSEADDR);
        if (new_socket == NULL)
        {
            tcp_send_rst(seg);
            printf("fail to new a tcp_sock\n");
            return;
        }

        tcp_sock_t *new_sock = new_socket;

        new_sock->parent = sk;

        new_sock->irs = seg->seq;
        new_sock->adv_wnd = seg->rx_win;
        new_sock->rcv_nxt = seg->seq + 1;

        tcp_handle_syn_option(new_sock, seg);

        tcp_set_state(new_sock, TCP_SYN_RECV);
        new_socket->can_free = true; // 在建立完成前是可以释放的
    }
}

// can recv SYN or SYN|ACK
void tcp_synsent_recv(tcp_sock_t *sk, tcp_segment *seg)
{
    // 直接释放
    free_mbuf(seg->data);

    if (likely(seg_set_ack(seg)))
    {
        // expect ack is snd_max(iss + 1)
        if (unlikely(seg->ack != sk->snd_max))
        {
            // if RST is set, drop the seg and return
            if (!seg_set_rst(seg))
                tcp_send_rst(seg);
            return;
        }
    }

    // note: when reach here, ack is acceptable or no ACK set
    if (unlikely(seg_set_rst(seg)))
    {
        if (seg_set_ack(seg))
        { // ack is acceptable here
            // TODO: signal to the user "error:connection reset"
            tcp_set_state(sk, TCP_CLOSED);
        }
        return;
    }

    // check the security

    // reach here only if the ACK is ok, or there is no ACK, and the segment did not contain an RST.
    if (seg_set_syn(seg))
    {
        sk->irs = seg->seq;
        sk->rcv_nxt = seg->seq + 1;

        if (seg_set_ack(seg))
        { // recv SYN|ACK, 正常流程
            sk->snd_una = seg->ack;
            sk->adv_wnd = seg->rx_win; // 更新发送窗口
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
            tcp_handle_syn_option(sk, seg);
            tcp_timer_stop(sk, TCPT_REXMT); // 收到了对自己SYN的ack，停止重传计时器
            tcp_set_state(sk, TCP_ESTABLISHED);
            tcp_send_ack(sk, false); // 立即发送对对方SYN的ack

            tcp_accept_conn(sk);

            return;
        }

        // 只收到SYN, 适合同时发送SYN的情况
        tcp_handle_syn_option(sk, seg);
        tcp_set_state(sk, TCP_SYN_RECV);
        tcp_timer_stop(sk, TCPT_REXMT);
        sk->snd_nxt = sk->snd_una; // 已经发送过SYN了，后面需要发送SYN|ACK
    }
}

void tcp_estab_recv(tcp_sock_t *sk, tcp_segment *seg)
{
    // 检查seq
    if (!acceptable_seq(sk, seg))
    {
        free_mbuf(seg->data);
        if (!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return;
    }

    // check RST
    if (seg_set_rst(seg))
    {
        free_mbuf(seg->data);
        if (sk->rcv_nxt == seg->seq)
        {
            tcp_set_state(sk, TCP_CLOSED);
        }
        else
        { // rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    // check SYN
    if (seg_set_syn(seg))
    {
        free_mbuf(seg->data);
        tcp_send_ack(sk, false);
        return;
    }

    // check ACK: 没有ACK就直接丢弃
    if (unlikely(!seg_set_ack(seg)))
    {
        free_mbuf(seg->data);
        return;
    }
    tcp_handle_ack(sk, seg);

    // recv data
    if (seg->data_len == 0) // 没有数据
    {
        free_mbuf(seg->data); // 释放
    }
    else
    {
        tcp_handle_data(sk, seg);
    }

    // check the FIN
    if (seg_set_fin(seg))
        tcp_handle_fin(sk);
}

void tcp_closed_recv(tcp_sock_t *sk, tcp_segment *seg)
{
    // 直接释放
    free_mbuf(seg->data);

    FNP_WARN("can't find tcp socket\n");
    if (!seg_set_rst(seg)) // 不是RST包
        tcp_send_rst(seg);
}
