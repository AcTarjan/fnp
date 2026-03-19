#include "fnp_worker.h"
#include "tcp_sock.h"
#include "tcp_ofo.h"
#include "tcp_in.h"
#include "tcp_out.h"

#include <unistd.h>
#include <rte_tcp.h>
#include <rte_ip.h>

#include "tcp_timer.h"

typedef void (*tcp_incoming_data_handler_func)(tcp_sock_t* sock, tcp_segment* seg);
static tcp_incoming_data_handler_func tcp_incoming_data_handler[TCP_STATE_END];

static inline void tcp_handle_syn_option(tcp_sock_t* sk, tcp_segment* seg)
{
    if (seg_has_opt(seg))
    {
        if (unlikely(seg_set_syn(seg)))
        {
            if (seg->opt.mss != 0)
            {
                // 支持MSS选项
                sk->mss = FNP_MIN(sk->mss, seg->opt.mss);
            }

            // 支持
            if (seg->opt.wnd_scale != 255)
            {
                // 支持窗口扩展
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
static inline bool acceptable_seq(tcp_sock_t* sk, tcp_segment* seg)
{
    if (unlikely(seg->data_len == 0))
        return SEQ_LE(sk->rcv_nxt, seg->seq) && SEQ_LT(seg->seq, sk->rcv_nxt + sk->rcv_wnd);

    const u32 end_seq = seg->seq + seg->data_len - 1;
    return SEQ_LE(sk->rcv_nxt, seg->seq) && SEQ_LT(end_seq, sk->rcv_nxt + sk->rcv_wnd);
}

static inline void tcp_handle_ack(tcp_sock_t* sk, tcp_segment* seg)
{
    // RFC5961: snd_una - max_snd_wnd =< ack =< snd_max
    //  ack值必须满足上述要求
    if (SEQ_GT(sk->snd_una - sk->max_snd_wnd, seg->ack) || SEQ_GT(seg->ack, sk->snd_nxt))
    {
        tcp_send_ack(sk, false);
        return;
    }

    // snd_una < ack <= snd_nxt
    if (likely(SEQ_LT(sk->snd_una, seg->ack) && SEQ_LE(seg->ack, sk->snd_nxt)))
    {
        sk->dup_ack = 0;
        sk->snd_una = seg->ack;
        tcp_ack_pending_list(sk, seg->ack);
    }
    else if (seg->ack == sk->snd_una)
    {
        sk->dup_ack++;
        if (sk->dup_ack > 2)
        {
            sk->dup_ack = 0;
            // TODO: 更新拥塞窗口
            tcp_start_retransmit(sk);
        }
    }
    else if (SEQ_GT(seg->ack, sk->snd_nxt)) // 确认了未发送的seq
    {
        tcp_send_ack(sk, false);
        return;
    }

    // snd.una =< ack =< snd.max, 更新发送窗口
    if (SEQ_LE(sk->snd_una, seg->ack) && SEQ_LE(seg->ack, sk->snd_nxt))
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
    if (sk->snd_una == sk->snd_nxt)
    {
        tcp_stop_retransmit_timer(sk); // 停止重传计时器
        switch (tcp_get_state(sk))
        {
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
            {
                tcp_set_state(sk, TCP_ESTABLISHED);
                break;
            }
        case TCP_FIN_WAIT_1:
            {
                // 如果ack了自己发送的FIN, local->remote单向关闭已完成
                tcp_set_state(sk, TCP_FIN_WAIT_2);
                // TODO: 向user调用返回ok
                break;
            }
        case TCP_CLOSING:
            {
                // 自己已发送FIN，也收到了对端的FIN（回ACK了），现在又收到了对端对FIN的ACK
                tcp_start_2msl_timer(sk);
                tcp_set_state(sk, TCP_TIME_WAIT);
                break;
            }
        case TCP_TIME_WAIT:
            {
                // 之前发送的对FIN的ACK丢失
                tcp_send_ack(sk, false);
                tcp_start_2msl_timer(sk);
                break;
            }
        case TCP_LAST_ACK:
            {
                // 已收到FIN，并且自己也发送了FIN，这个ACK是对自己发送FIN的确认
                tcp_set_state(sk, TCP_CLOSED);
                break;
            }
        }
    }
}


int tcp_deliver_data_to_app(fsocket_t* socket, struct rte_mbuf* data)
{
    struct rte_mbuf* m = clone_mbuf(data);
    if (unlikely(m == NULL))
        return 0;

    if (unlikely(fsocket_enqueue_for_app(socket, m) == 0))
    {
        FNP_WARN("can't enqueue tcp data!!!!!!\n");
        free_mbuf(m);
        return 0;
    }

    return 1;
}

void tcp_handle_fin(tcp_sock_t* sock)
{
    if (likely(!sock->fin_received))
    {
        // 修改socket标记来通知应用层
        fsocket_t* socket = fsocket(sock);
        socket->fin_received = 1;
        sock->fin_received = 1;
        sock->rcv_nxt++; // FIN占用一个序列号
    }

    tcp_send_ack(sock, false);

    // 状态处理
    i32 state = tcp_get_state(sock);
    switch (state)
    {
    case TCP_SYN_RECV:
    case TCP_ESTABLISHED:
        {
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
            tcp_start_2msl_timer(sock);
            break;
        }
    }
}

// 返回0继续处理FIN, 返回1表示收到乱序的数据包，稍后处理FIN
static inline void tcp_handle_data(tcp_sock_t* sock, tcp_segment* seg)
{
    // 收到顺序的包
    if (likely(sock->rcv_nxt == seg->seq))
    {
        fsocket_t* socket = fsocket(sock);
        if (likely(tcp_deliver_data_to_app(socket, seg->data)))
        {
            sock->rcv_nxt += seg->data_len;

            // check out of order
            tcp_ofo_handle_seg(sock);
            tcp_send_ack(sock, true);
        }
        return;
    }

    // 乱序的数据包，先不处理FIN
    tcp_ofo_seg* ofo_seg = tcp_ofo_init(seg);
    if (ofo_seg == NULL)
    {
        printf("fail to alloc tcp_ofo_seg\n");
        return;
    }
    seg->flags = 0; // 去掉FIN标记
    tcp_ofo_enqueue_seg(sock, ofo_seg);
    tcp_send_ack(sock, false); // 收到乱序的数据，立即回ACK
}

static inline void tcp_accept_conn(tcp_sock_t* sock)
{
    if (likely(sock->parent != NULL))
    {
        tcp_sock_t* parent = sock->parent;
        fsocket_t* socket = &sock->socket;
        socket->frontend_id = parent->socket.frontend_id; // 不能被释放, 如果释放, 出队列的socket会内存错误.
        if (!fsocket_enqueue_for_app((fsocket_t*)parent, socket))
        {
            FNP_WARN("can't enqueue socket!!!\n");
            free_fsocket(socket);
        }
    }
}

// 收到重传的SYN
// 收到SYN|ACK
// 收到ACK
// 收到数据包（可能乱序），对方已经是ESTABLISHED状态
void tcp_synrecv_recv(tcp_sock_t* sk, tcp_segment* seg)
{
    //check seq is ok?
    if (unlikely(!acceptable_seq(sk, seg) && seg->seq != sk->irs))
    {
        if (!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return;
    }

    // check RST
    if (unlikely(seg_set_rst(seg)))
    {
        if (sk->rcv_nxt == seg->seq)
        {
            tcp_set_state(sk, TCP_CLOSED);
        }
        else
        {
            // rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    // check SYN
    if (unlikely(seg_set_syn(seg)))
    {
        if (seg->seq == sk->irs)
        {
            if (seg_set_ack(seg))
            {
                // recv SYN|ACK for our SYN, 适用于同时发送SYN
                if (seg->ack == sk->snd_nxt)
                {
                    tcp_handle_syn_option(sk, seg);
                    tcp_handle_ack(sk, seg);
                    tcp_accept_conn(sk);
                }
                else
                {
                    tcp_send_rst(seg);
                    return; // 不确定是否drop
                }
            }
            else
            {
                // 收到对方重传的SYN, 立即重传SYN|ACK
                tcp_send_syn(sk);
            }
        }
        else
        {
            // recv a new syn again
            tcp_set_state(sk, TCP_CLOSED);
        }
        return;
    }

    // only recv ack
    if (likely(seg_set_ack(seg)))
    {
        // check ACK
        if (likely(seg->ack == sk->snd_nxt))
        {
            // reach here only set ACK
            tcp_handle_ack(sk, seg);
            if (seg->data_len != 0)
                tcp_handle_data(sk, seg); // 处理数据

            // 如果入队失败, 会释放socket
            tcp_accept_conn(sk);
            return;
        }

        tcp_send_rst(seg);
    }
}

void tcp_listen_recv(tcp_sock_t* sk, tcp_segment* seg)
{
    // 检查RST
    if (unlikely(seg_set_rst(seg)))
    {
        return;
    }

    // 检查ACK, any ack is bad
    if (unlikely(seg_set_ack(seg)))
    {
        tcp_send_rst(seg);
        return;
    }

    // 检查SYN
    if (likely(seg_set_syn(seg)))
    {
        /*
         * TCP passive connection creation is intentionally disabled until TCP
         * is migrated to the conf-only socket creation path.
         */
        tcp_send_rst(seg);
        return;
    }
}

// can recv SYN or SYN|ACK
void tcp_synsent_recv(tcp_sock_t* sk, tcp_segment* seg)
{
    if (likely(seg_set_ack(seg)))
    {
        // expect ack is snd_max(iss + 1)
        if (unlikely(seg->ack != sk->snd_nxt))
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
        // ack is ok
        if (seg_set_ack(seg))
        {
            // ack is acceptable here
            // TODO: signal to the user "error:connection reset"
            tcp_set_state(sk, TCP_CLOSED);
        }
        return;
    }

    // reach here only if the ACK is ok, or there is no ACK, and the segment did not contain an RST.
    if (likely(seg_set_syn(seg)))
    {
        sk->irs = seg->seq;
        sk->rcv_nxt = seg->seq + 1;
        tcp_handle_syn_option(sk, seg);

        // 收到SYN|ACK
        if (likely(seg_set_ack(seg)))
        {
            // recv SYN|ACK, 正常流程
            tcp_handle_ack(sk, seg);
            tcp_send_ack(sk, false); // 立即发送对对方SYN的ack
            tcp_accept_conn(sk);
            return;
        }

        // 只收到SYN, 适用于同时发送SYN的情况
        tcp_set_state(sk, TCP_SYN_RECV);
    }
}

void tcp_estab_recv(tcp_sock_t* sk, tcp_segment* seg)
{
    // 检查seq
    if (!acceptable_seq(sk, seg))
    {
        if (!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return;
    }

    // check RST
    if (seg_set_rst(seg))
    {
        if (sk->rcv_nxt == seg->seq)
        {
            tcp_set_state(sk, TCP_CLOSED);
        }
        else
        {
            // rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    // check SYN
    if (seg_set_syn(seg))
    {
        tcp_send_ack(sk, false);
        return;
    }

    // check ACK: 没有ACK就直接丢弃
    if (unlikely(!seg_set_ack(seg)))
    {
        return;
    }
    tcp_handle_ack(sk, seg);

    // recv data
    if (likely(seg->data_len != 0)) // 没有数据
    {
        tcp_handle_data(sk, seg);
    }

    // check the FIN
    if (unlikely(seg_set_fin(seg)))
        tcp_handle_fin(sk);
}

void tcp_closed_recv(tcp_sock_t* sk, tcp_segment* seg)
{
    if (likely(!seg_set_rst(seg))) // 不是RST包
        tcp_send_rst(seg);
}


static inline void tcp_decode_option(tcp_option* opt, u8* bytes, u8 len)
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
            {
                // NOP
                index++;
                break;
            }
        case 2:
            {
                // MSS
                u16* mss = bytes + index + 2;
                opt->mss = fnp_swap16(*mss);
                index += 4;
                break;
            }
        case 3:
            {
                // Window Scale
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

static inline void tcp_seg_init(struct rte_mbuf* m, tcp_segment* seg)
{
    struct rte_ipv4_hdr* ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u8 ipv4_hdr_len = rte_ipv4_hdr_len(ipv4Hdr);
    struct rte_tcp_hdr* tcpHdr = (struct rte_tcp_hdr*)rte_pktmbuf_adj(m, ipv4_hdr_len);

    seg->iface_id = m->port;
    seg->proto = IPPROTO_TCP;
    seg->remote.family = FSOCKADDR_IPV4;
    seg->remote.ip = ipv4Hdr->src_addr;
    seg->remote.port = tcpHdr->src_port;
    seg->local.family = FSOCKADDR_IPV4;
    seg->local.ip = ipv4Hdr->dst_addr;
    seg->local.port = tcpHdr->dst_port;
    seg->flags = tcpHdr->tcp_flags;
    seg->hdr_len = tcpHdr->data_off >> 2;
    seg->seq = fnp_swap32(tcpHdr->sent_seq);
    seg->ack = fnp_swap32(tcpHdr->recv_ack);
    seg->rx_win = fnp_swap16(tcpHdr->rx_win);
    seg->data_len = fnp_swap16(ipv4Hdr->total_length) - ipv4_hdr_len - seg->hdr_len;

    if (seg_has_opt(seg))
    {
        u8* opt_bytes = rte_pktmbuf_mtod_offset(m, u8 *, TCP_HDR_MIN_LEN);
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

void tcp_socket_recv(fsocket_t* socket, struct rte_mbuf* m)
{
    tcp_segment seg;
    tcp_seg_init(m, &seg);
    tcp_sock_t* sock = (tcp_sock_t*)socket;
    i32 state = tcp_get_state(sock);

    // mbuf在tcp_recv中释放, 释放mbuf不影响seg
    tcp_incoming_data_handler[state](sock, &seg);

    //释放数据
    free_mbuf(m);
}

// 可以将连接置为CLOSED状态, 但不能tcp_free_sock释放资源, 由用户调用tcp_free_sock释放资源
void tcp_recv_mbuf_from_ipv4(struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    fsocket_t* socket = lookup_transport_socket_by_ipv4(ipv4_hdr);
    if (unlikely(socket == NULL))
    {
        free_mbuf(m);
        return;
    }

    tcp_socket_recv(socket, m);
}


void tcp_recv_init()
{
    tcp_incoming_data_handler[TCP_NEW] = tcp_closed_recv;
    tcp_incoming_data_handler[TCP_LISTEN] = tcp_listen_recv;
    tcp_incoming_data_handler[TCP_SYN_SENT] = tcp_synsent_recv;
    tcp_incoming_data_handler[TCP_SYN_RECV] = tcp_synrecv_recv;
    tcp_incoming_data_handler[TCP_ESTABLISHED] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_CLOSE_WAIT] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_LAST_ACK] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_FIN_WAIT_1] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_FIN_WAIT_2] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_CLOSING] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_TIME_WAIT] = tcp_estab_recv;
    tcp_incoming_data_handler[TCP_CLOSED] = tcp_closed_recv;
}
