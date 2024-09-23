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

void tcp_write_options(tcp_sock_t* sk, struct rte_tcp_hdr* hdr, bool syn)
{
    u8* optStart = (u8*)(hdr + 1);
    u8 i = 0;

    if(syn) {
        // Maximum Segment Size Option
        optStart[i] = 2;
        optStart[i + 1] = 4;
        u16 *mss = optStart + i + 2;
        *mss = fnp_swap_16(sk->mss);
        i += 4;


        //Window Scale option, shift count = 7
        optStart[i] = 3;
        optStart[i + 1] = 3;
        optStart[i + 2] = sk->rcv_wnd_scale;
        i += 3;

        //permit sack
//        optStart[i] = 4;
//        optStart[i + 1] = 2;
//        i += 2;
    }

    //End of Option List Option
    while (i % 4 != 0) {
        optStart[i] = 0;
        i++;
    }

}

void tcp_send_syn(tcp_sock_t* sk, rte_mbuf* m, u8 flags) {
    sk->rcv_wnd = fnp_ring_avail(sk->rxbuf);
    sk->snd_nxt = sk->iss;

    u8 hdr_len = TCP_HDR_MIN_LEN + 8;

    struct rte_tcp_hdr* hdr = (struct rte_tcp_hdr*) rte_pktmbuf_prepend(m, hdr_len);
    hdr->src_port = sk->port;
    hdr->dst_port = sk->rport;
    hdr->sent_seq = fnp_swap_32(sk->snd_nxt);
    hdr->recv_ack = fnp_swap_32(sk->rcv_nxt);
    hdr->tcp_flags = flags;
    hdr->rx_win = fnp_swap_16(sk->rcv_wnd);         //此时不进行窗口缩放
    hdr->cksum = 0;
    hdr->tcp_urp = fnp_swap_16(sk->snd_up);
    hdr->data_off = ((hdr_len) / 4) << 4;

    tcp_write_options(sk, hdr, true);

//    m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

    ipv4_send_mbuf(m, sk->rip, IPPROTO_TCP);
}

void tcp_send_data(tcp_sock_t* sk, rte_mbuf* m, u8 flags)
{
    sk->rcv_wnd = fnp_ring_avail(sk->rxbuf);
    u8 hdr_len = TCP_HDR_MIN_LEN;


    struct rte_tcp_hdr* hdr = (struct rte_tcp_hdr*) rte_pktmbuf_prepend(m, hdr_len);
    hdr->src_port = sk->port;
    hdr->dst_port = sk->rport;
    hdr->sent_seq = fnp_swap_32(sk->snd_nxt);
    hdr->recv_ack = fnp_swap_32(sk->rcv_nxt);
    hdr->tcp_flags = flags;
    hdr->rx_win = fnp_swap_16(sk->rcv_wnd >> sk->rcv_wnd_scale);
    hdr->cksum = 0;
    hdr->tcp_urp = fnp_swap_16(sk->snd_up);
    hdr->data_off = ((hdr_len) / 4) << 4;

    tcp_write_options(sk, hdr, false);
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
    if(likely(delay)) {
        if (tcp_timer_is_running(sk, TCPT_DELAY_ACK))
            return;
        tcp_timer_start(sk, TCPT_DELAY_ACK);
    } else {
        struct rte_mbuf* m = fnp_alloc_mbuf();
        m->port = sk->id;
        tcp_send_data(sk, m, RTE_TCP_ACK_FLAG);
    }
}

//send SYN or SYN|ACK
void tcp_syn_send(tcp_sock_t* sk) {
    if (sk->snd_nxt == sk->snd_una) {  //还未发送过SYN
        struct rte_mbuf *m = fnp_alloc_mbuf();
        if (m == NULL) {
            printf("fnp_alloc_mbuf failed\n");
            return;
        }
        m->port = sk->id;
        tcp_send_syn(sk, m, tcp_outflags[tcp_state(sk)]);
        sk->snd_nxt += 1;

        //启动重传定时器
        tcp_timer_start(sk, TCPT_REXMT);
    }
}

//send tcp segment
void tcp_data_send(tcp_sock_t* sk) {
    for(i32 i = 0; i < TCP_MAX_SEND_BURST; i++) {
        //当触发重传后，结果收到了ACK，导致snd_una变大, 要保证：snd_nxt >= snd_una
        sk->snd_nxt = FNP_MAX(sk->snd_una, sk->snd_nxt);
        u8 flags = tcp_outflags[tcp_state(sk)];
        //待发送数据: 包括用户数据, FIN
        i32 data_len = fnp_ring_len(sk->txbuf) + (flags & RTE_TCP_FIN_FLAG);
        //从还没发送过的数据开始发送，snd_una为窗口下界。当重传时，只需要让 snd_nxt = snd_una
        i32 data_offset = (i32) (sk->snd_nxt - sk->snd_una);

        //have data to send
        if (data_len - data_offset > 0) {
            sk->snd_wnd = FNP_MIN(sk->adv_wnd << sk->snd_wnd_scale, sk->cwnd * sk->mss);
            i32 win = FNP_MIN(sk->snd_wnd - data_offset, sk->mss);
            if(win <= 0) {      //虽然有数据，发送窗口内的数据都已经发送完了
                break;
            }

            struct rte_mbuf *m = fnp_alloc_mbuf();
            if(m == NULL) {
                printf("fnp_alloc_mbuf failed\n");
                return ;
            }
            m->port = sk->id;
            u8 *buf = rte_pktmbuf_mtod(m, u8*);

            i32 len = fnp_ring_top(sk->txbuf, buf, data_offset, win);
            m->pkt_len += len;
            m->data_len += len;

            //如果不是最后一个包，不能携带FIN
            if (likely(data_len > data_offset + len + (flags & RTE_TCP_FIN_FLAG))) {
                flags &= ~RTE_TCP_FIN_FLAG;
            }

            tcp_send_data(sk, m, flags);

            sk->snd_nxt += len;
            sk->snd_nxt += (flags & RTE_TCP_FIN_FLAG);

            if (SEQ_LT(sk->snd_max, sk->snd_nxt))
                sk->snd_max = sk->snd_nxt;


            //如果重传定时器没有启动，则启动它
            if (unlikely(!tcp_timer_is_running(sk, TCPT_REXMT))) {
                tcp_timer_start(sk, TCPT_REXMT);
            }

            //如果延迟ACK启动了，则停止它
            if (tcp_timer_is_running(sk, TCPT_DELAY_ACK)) {
                tcp_timer_stop(sk, TCPT_DELAY_ACK);
            }
            continue;       // 可能还有数据要发送
        }
        break;
    }
}


extern fnp_hash_t* tcpSockTbl;

void tcp_handle_user_req(tcp_sock_t* sk) {
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
}

void tcp_socket_output() {
    u8* key;  tcp_sock_t* sk; i32 next = 0;
    while (fnp_hash_iterate(tcpSockTbl, &key, &sk, &next)) {
        if(tcp_state(sk) > TCP_LISTEN) {
            tcp_handle_user_req(sk);
            sk->tcp_send(sk);
        }
    }
}