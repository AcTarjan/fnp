#include "inc/fnp_tcp_sock.h"
#include "inc/fnp_tcp_in.h"
#include "inc/fnp_tcp_comm.h"
#include "inc/fnp_tcp_timer.h"
#include "fnp_ipv4.h"


#include <netinet/ip.h>

static u8 tcp_outflags[TCP_STATE_END] = {
        RTE_TCP_RST_FLAG|RTE_TCP_ACK_FLAG, 0, RTE_TCP_SYN_FLAG, RTE_TCP_SYN_FLAG|RTE_TCP_ACK_FLAG,
        RTE_TCP_ACK_FLAG, RTE_TCP_ACK_FLAG,
        RTE_TCP_FIN_FLAG|RTE_TCP_ACK_FLAG, RTE_TCP_FIN_FLAG|RTE_TCP_ACK_FLAG, RTE_TCP_FIN_FLAG|RTE_TCP_ACK_FLAG,
        RTE_TCP_ACK_FLAG, RTE_TCP_ACK_FLAG,
};

void tcp_write_options(struct rte_tcp_hdr* hdr, struct tcp_option* opts)
{
    u8* opt_start = (u8*)(hdr + 1);
    u8 i = 0;
    // mss
    opt_start[i] = 2;
    opt_start[i+1] = 4;
    u16* mss = opt_start + i + 2;
    *mss = fnp_swap_16(opts->mss);
    i += 4;

    //permit sack
    opt_start[i] = 4;
    opt_start[i+1] = 2;
    i += 2;

    //wsopt
    opt_start[i] = 3;
    opt_start[i+1] = 3;
    opt_start[i+2] = 7;
    i += 3;

    //nop
    opt_start[i] = 1;
    i += 1;

    //tsopt
    opt_start[i] = 8;
    opt_start[i+1] = 10;
    u32* ts = opt_start + i + 2;
    *ts = opts->ts.ts_val;
    ts = opt_start + i + 6;
    *ts = opts->ts.ts_ecr;
    i += 10;
}

void tcp_sendto_ip(tcp_sock_t* sk, rte_mbuf* m, u8 flags)
{
    if(unlikely(flags & RTE_TCP_SYN_FLAG)) {
        sk->snd_nxt = sk->iss;
    }

    sk->rcv_wnd = fnp_ring_avail(sk->rxbuf);
    struct rte_tcp_hdr* hdr = (struct rte_tcp_hdr*) rte_pktmbuf_prepend(m, 20);
    hdr->src_port = sk->lport;
    hdr->dst_port = sk->rport;
    hdr->sent_seq = fnp_swap_32(sk->snd_nxt);
    hdr->recv_ack = fnp_swap_32(sk->rcv_nxt);
    hdr->tcp_flags = flags;
    hdr->data_off = (20 / 4) << 4;
    hdr->rx_win = fnp_swap_16(sk->rcv_wnd);
    hdr->cksum = 0;
    hdr->tcp_urp = fnp_swap_16(sk->snd_up);

//    m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

    ipv4_send_mbuf(m, sk->rip, IPPROTO_TCP);
}

void tcp_send_rst(tcp_seg_t* seg) {
    rte_mbuf* m = fnp_alloc_mbuf();
    m->port = seg->iface_id;

    struct rte_tcp_hdr* hdr = (struct rte_tcp_hdr*) rte_pktmbuf_prepend(m, TCP_HDR_MIN_LEN);
    hdr->src_port = seg->lport;
    hdr->dst_port = seg->rport;
    hdr->tcp_flags = RTE_TCP_RST_FLAG;
    hdr->data_off = 0x50;
    hdr->rx_win = 0;
    hdr->cksum = 0;
    hdr->tcp_urp = 0;
    if(seg->flags & RTE_TCP_ACK_FLAG) {
        hdr->sent_seq = fnp_swap_32(seg->ack);
    } else {
        hdr->tcp_flags |= RTE_TCP_ACK_FLAG;
        hdr->sent_seq = 0;
        u32 recv_ack = seg->seq + seg->data_len;
        if(seg->flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))
            recv_ack += 1;
        hdr->recv_ack = fnp_swap_32(recv_ack);
    }

//    m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

    ipv4_send_mbuf(m, seg->rip, IPPROTO_TCP);
}

void tcp_send_ack(tcp_sock_t* sk, bool delay)
{
    struct rte_mbuf* m = fnp_alloc_mbuf();
    m->port = sk->iface->id;

    if(likely(delay)) {
        tcp_timer_start(sk, TCPT_DELAY_ACK);
    } else
        tcp_sendto_ip(sk, m, RTE_TCP_ACK_FLAG);
}

void tcp_send_syn(tcp_sock_t* sk)
{
    struct rte_mbuf* m = fnp_alloc_mbuf();
    m->port = sk->iface->id;

    tcp_sendto_ip(sk, m, RTE_TCP_SYN_FLAG);
}

//send tcp segment
void tcp_output(tcp_sock_t* sk) {
    // 处理用户调用
    if (sk->user_req & TCP_USER_CLOSE) {
        sk->user_req &= ~TCP_USER_CLOSE;
        if(tcp_state(sk) == TCP_CLOSE_WAIT)
            tcp_set_state(sk, TCP_LAST_ACK);
        else
            tcp_set_state(sk, TCP_FIN_WAIT_1);
    }

    if (sk->user_req & TCP_USER_CONNECT) {
        sk->user_req &= ~TCP_USER_CONNECT;
        tcp_set_state(sk, TCP_SYN_SENT);
    }

    while (1) {
        //当触发重传后，结果收到了ACK，导致snd_una变大, 要保证：snd_nxt >= snd_una
        sk->snd_nxt = FNP_MAX(sk->snd_una, sk->snd_nxt);
        u8 flags = tcp_outflags[tcp_state(sk)];
        //待发送数据: 包括用户数据、SYN和FIN
        i32 data_len = fnp_ring_len(sk->txbuf) + (flags & RTE_TCP_FIN_FLAG) + (flags & RTE_TCP_SYN_FLAG ? 1 : 0);
        //从还没发送过的数据开始发送，snd_una为窗口下界。当重传时，只需要让 snd_nxt = snd_una
        i32 data_offset = (i32) (sk->snd_nxt - sk->snd_una);

        //have data to send
        if (data_len - data_offset > 0) {
            sk->snd_wnd = FNP_MIN(sk->adv_wnd, sk->cwnd * TCP_MAX_SEG_SIZE);
            i32 win = FNP_MIN(sk->snd_wnd - data_offset, TCP_MAX_SEG_SIZE);
            if(win <= 0) {      //虽然有数据，发送窗口内的数据都已经发送完了
                return;
            }

            struct rte_mbuf *m = fnp_alloc_mbuf();
            if(m == NULL) {
                printf("fnp_alloc_mbuf failed\n");
                return ;
            }
            m->port = sk->iface->id;
            u8 *buf = rte_pktmbuf_mtod(m, u8*);

            i32 len = fnp_ring_top(sk->txbuf, buf, data_offset, win);
            m->pkt_len += len;
            m->data_len += len;

            // SYN必定是第一个包，因为现在没有数据

            //如果不是最后一个包，不能携带FIN
            if (likely(data_offset + len + (flags & RTE_TCP_FIN_FLAG) < data_len)) {
                flags &= ~RTE_TCP_FIN_FLAG;
            }

            tcp_sendto_ip(sk, m, flags);

            sk->snd_nxt += len;
            if (unlikely(flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG))) {
                sk->snd_nxt += 1;
            }

            if (SEQ_LT(sk->snd_max, sk->snd_nxt))
                sk->snd_max = sk->snd_nxt;

            //如果重传定时器没有启动，则启动它
            if (unlikely(!tcp_timer_is_running(sk, TCPT_REXMT))) {
                tcp_timer_start(sk, TCPT_REXMT);
            }

            //延迟ACK
            if (tcp_timer_is_running(sk, TCPT_DELAY_ACK)) {
                tcp_timer_stop(sk, TCPT_DELAY_ACK);
            }
        } else {
            return;
        }
    }
}