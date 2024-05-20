#include "fnp_init.h"
#include "fnp_tcp.h"
#include "fnp_tcp_ofo.h"
#include "fnp_tcp_timer.h"
#include <rte_tcp.h>
#include <rte_ip.h>
#include <unistd.h>


void tcp_parse_options(tcp_option_t* opt, u8* bytes, u8 len) {
    u8 index = 0;
    opt->mss = TCP_MAX_SEG_SIZE;
    opt->wnd_scale = 0;
    while (index < len) {
        switch (bytes[index]) {
            case 0:         // EOL
                return;
            case 1: {         // NOP
                index++;
                break;
            }
            case 2: {         //MSS
                u16* mss = bytes + index + 2;
                opt->mss = fnp_swap_16(*mss);
                index += 4;
                break;
            }
            case 4: {
                opt->permit_sack = 1;
                index += 2;
                break;
            }
            case 8: {
                fnp_memcpy(&opt->ts, bytes + index + 2, 8);
                index += 10;
                break;
            }
            default: {
                u8 olen = bytes[index + 1];
                index += olen;
            }
        }
    }

}

void tcp_seg_init(rte_mbuf* m, tcp_seg_t* seg)
{
    struct rte_ipv4_hdr* ipv4Hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    u8 ipv4_hdr_len = rte_ipv4_hdr_len(ipv4Hdr);
    struct rte_tcp_hdr* tcpHdr = (struct rte_tcp_hdr*) rte_pktmbuf_adj(m, ipv4_hdr_len);

    seg->iface_id = m->port;
    seg->rip = ipv4Hdr->src_addr;
    seg->lip = ipv4Hdr->dst_addr;
    seg->rport = tcpHdr->src_port;
    seg->lport = tcpHdr->dst_port;
    seg->flags = tcpHdr->tcp_flags;
    seg->hdr_len = tcpHdr->data_off >> 2;
    seg->seq = fnp_swap_32(tcpHdr->sent_seq);
    seg->ack = fnp_swap_32(tcpHdr->recv_ack);
    seg->rx_win = fnp_swap_16(tcpHdr->rx_win);
    seg->data_len = fnp_swap_16(ipv4Hdr->total_length) - ipv4_hdr_len - seg->hdr_len;

//    u8* opt_bytes = rte_pktmbuf_mtod_offset(m, u8*, TCP_HDR_MIN_LEN);
//    tcp_parse_options(&seg->opt, opt_bytes, seg->hdr_len - TCP_HDR_MIN_LEN);

    seg->data = rte_pktmbuf_adj(m, seg->hdr_len);
}

static i32 tcp_lookup_sock(tcp_seg_t* cb, tcp_sock_t** sk)
{
    tcp_sock_key_t key = {cb->lip, cb->rip, cb->lport, cb->rport};
    if(unlikely(fnp_lookup_hash(conf.tcpSockTbl, &key, sk) == 0))
    {
        key.rip = 0;
        key.rport = 0;
        return fnp_lookup_hash(conf.tcpSockTbl, &key, sk);
    }

    return 1;
}


u8 acceptable_seq(tcp_sock_t* sk, tcp_seg_t* cb)
{
    if(unlikely(cb->data_len == 0))
        return SEQ_LE(sk->rcv_nxt, cb->seq) && SEQ_LT(cb->seq, sk->rcv_nxt + sk->rcv_wnd);

    const u32 end_seq = cb->seq + cb->data_len - 1;
    return (SEQ_LE(sk->rcv_nxt, cb->seq) && SEQ_LT(cb->seq, sk->rcv_nxt + sk->rcv_wnd)) ||
           (SEQ_LE(sk->rcv_nxt, end_seq) && SEQ_LT(end_seq, sk->rcv_nxt + sk->rcv_wnd));
}

void tcp_listen_handle(tcp_sock_t* sk, tcp_seg_t* seg)  {
    //check for an RST
    if(seg_set_rst(seg)) {
        return;
    }

    //check for an ACK, any ack is bad
    if(seg_set_ack(seg)) {
        tcp_send_rst(seg);
        return;
    }

    //check for a SYN
    if(seg_set_syn(seg)) {
        tcp_sock_t *newsk = fnp_tcp_sock(seg->lip, seg->lport, seg->rip, seg->rport);
        newsk->parent = sk;

        newsk->irs = seg->seq;
        newsk->adv_wnd = seg->rx_win;
        newsk->rcv_nxt = seg->seq + 1;

        tcp_set_state(newsk, TCP_SYN_RECV);
    }

}

void tcp_syn_sent_handle(tcp_sock_t* sk, tcp_seg_t* seg)  {
    if(seg_set_ack(seg)) {
        // ack is bad: ack =< iss or ack > snd.max
        if(SEQ_LE(seg->ack, sk->iss) || SEQ_GT(seg->ack, sk->snd_max)) {
            //if RST is set, drop the seg and return
            if(!seg_set_rst(seg))
                tcp_send_rst(seg);
            return ;
        }
    }

    //note: when reach here, ack is acceptable or no ACK set
    if(seg_set_rst(seg)) {
        if(seg_set_ack(seg)) {  // ack is acceptable here
            //TODO: signal to the user "error:connection reset"
            tcp_set_state(sk, TCP_CLOSED);
            tcp_free_sock(sk);
        }
        return;
    }

    //check the security

    //reach here only if the ACK is ok, or there is no ACK, and the segment did not contain an RST.
    if(seg_set_syn(seg)) {
        sk->irs = seg->seq;

        sk->rcv_nxt = seg->seq + 1;
        if(seg_set_ack(seg)) {  //recv SYN|ACK
            sk->snd_una = seg->ack;
            if(tcp_timer_is_running(sk, TCPT_REXMT)) {
                tcp_timer_stop(sk, TCPT_REXMT);
            }
            sk->snd_wnd = seg->rx_win;  //更新发送窗口
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
            tcp_set_state(sk, TCP_ESTABLISHED);
            if(sk->parent != NULL)
                fnp_ring_enqueue(sk->parent->accept, sk);
            tcp_send_ack(sk, false);
            return;
        }
        tcp_set_state(sk, TCP_SYN_RECV);
        if(tcp_timer_is_running(sk, TCPT_REXMT)) {
            tcp_timer_stop(sk, TCPT_REXMT);
            sk->snd_nxt = sk->snd_una;      //已经发送过SYN了，后面需要发送SYN|ACK
        }
    }
}

void tcp_handle_data(tcp_sock_t* sk, tcp_seg_t* seg) {
    i32 state = tcp_state(sk);
    if(likely(seg->data_len > 0 && (state == TCP_ESTABLISHED ||
        state == TCP_FIN_WAIT_1 || state == TCP_FIN_WAIT_2))) {
        if(seg->seq == sk->rcv_nxt) {
            i32 rx_len = fnp_ring_push(sk->rxbuf, seg->data, seg->data_len);
            sk->rcv_nxt += rx_len;
            if (rx_len > 0) {
                //check out of order
                u32 rcv_nxt = sk->rcv_nxt;
                while (tcp_ofo_top(sk->ofo_head, &rcv_nxt));
                fnp_ring_push(sk->rxbuf, NULL, (i32)(rcv_nxt - sk->rcv_nxt));
                sk->rcv_nxt = rcv_nxt;
                tcp_send_ack(sk, true);         //是否开启delay
            }
        } else {    // out of order
            i32 offset = (i32)(seg->seq - sk->rcv_nxt);
            i32 len = FNP_MIN(fnp_ring_avail(sk->rxbuf) - offset, seg->data_len);
            u32 seq = seg->seq;
            tcp_ofo_insert(sk->ofo_head, &seq, &len);
            if(len > 0) {
                fnp_ring_pre_push(sk->rxbuf, (i32)(seq - sk->rcv_nxt), seg->data + (seq - seg->seq), len);
            }
        }
    }
}

void tcp_handle_ack(tcp_sock_t* sk, tcp_seg_t* seg) {
    //RFC5961: snd_una - max_snd_wnd =< ack =< snd_max
    if(SEQ_LE(sk->snd_una - sk->max_snd_wnd, seg->ack) && SEQ_LE(seg->ack, sk->snd_max)) {

        // snd_una < ack <= snd_max
        if(SEQ_LT(sk->snd_una, seg->ack) && SEQ_LE(seg->ack, sk->snd_max)) {
            //注意：txbuf中不包括SYN和FIN，但是SYN和FIN占用1个seq，此时队列为空, 也pop不出来
            fnp_ring_pop(sk->txbuf, NULL, seg->ack - sk->snd_una);
            sk->dup_ack = 0;
            sk->snd_una = seg->ack;
            //确认了所有已发送的seq
            if(sk->snd_una == sk->snd_max) {
//                printf("recv ack to stop retransmission timer\n");
                sk->cwnd = FNP_MIN(sk->cwnd << 1, TCP_MAX_CWND);
                tcp_timer_stop(sk, TCPT_REXMT);
            }
        } else if(seg->ack == sk->snd_una) {
            sk->dup_ack++;
            if(sk->dup_ack > 2) {
                sk->dup_ack = 0;
                sk->snd_nxt = sk->snd_una;      //立即重传
//                printf("3 ack to stop retransmission timer\n");
                sk->cwnd = FNP_MIN(sk->cwnd, TCP_THRESHOLD);
                tcp_timer_stop(sk, TCPT_REXMT);
            }
        } else if(SEQ_GT(seg->ack, sk->snd_max)) {   //确认了未发送的seq
            tcp_send_ack(sk, false);
            return;
        }

        //snd.una =< seg.ack =< snd.max, 更新发送窗口
        if(SEQ_LE(sk->snd_una, seg->ack) && SEQ_LE(seg->ack, sk->snd_max)) {
            // The check here prevents using old segments to update the window.
            if(SEQ_LT(sk->snd_wl1, seg->seq) ||
               (sk->snd_wl1 == seg->seq && SEQ_LE(sk->snd_wl2, seg->ack))) {
                sk->adv_wnd = seg->rx_win;
                sk->snd_wl1 = seg->seq;
                sk->snd_wl2 = seg->ack;
            }
        }

        switch (sk->state) {
            case TCP_FIN_WAIT_1: {
                //如果ack了自己发送的FIN, local->remote单向关闭已完成
                if(sk->snd_una == sk->snd_max) {
                    tcp_set_state(sk, TCP_FIN_WAIT_2);
                    //TODO: 向user调用返回ok
                }
                break;
            }
            case TCP_CLOSING: {
                //自己已发送FIN，也收到了对端的FIN（回ACK了），现在又收到了对端对FIN的ACK
                if(sk->snd_una == sk->snd_max) {
                    tcp_set_state(sk, TCP_TIME_WAIT);
                    tcp_timer_start(sk, TCPT_2MSL);
                }
                break;
            }
            case TCP_LAST_ACK: {
                //已收到FIN，并且自己也发送了FIN，这个ACK是对自己发送FIN的确认
                if(sk->snd_una == sk->snd_max) {
                    tcp_set_state(sk, TCP_CLOSED);
                    tcp_free_sock(sk);
                }
                break;
            }
            case TCP_TIME_WAIT: {
                //之前发送的对FIN的ACK丢失
                tcp_send_ack(sk, false);
                tcp_timer_start(sk, TCPT_2MSL);
                break;
            }
        }

    } else {    //ack值有问题
        tcp_send_ack(sk, false);
        return;
    }
}

void tcp_syn_recv_handle(tcp_sock_t* sk, tcp_seg_t* seg) {
    if ((!acceptable_seq(sk, seg)) && seg->seq != sk->irs) {   //check whether seq is valid
        if (!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return ;
    }

    if (seg_set_rst(seg)) {                  //check RST
        if (sk->rcv_nxt == seg->seq) {
            tcp_set_state(sk, TCP_CLOSED);
            tcp_free_sock(sk);
        } else {    //rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    if (seg_set_syn(seg)) {                      //check SYN
        if (seg->seq == sk->irs) {
            if(seg_set_ack(seg)) {              //recv SYN|ACK for our SYN, 适用于同时发送SYN
                if(seg->ack == sk->snd_max) {
                    sk->snd_una = seg->ack;
                    tcp_timer_stop(sk, TCPT_REXMT);
                    sk->adv_wnd = seg->rx_win;
                    sk->snd_wl1 = seg->seq;
                    sk->snd_wl2 = seg->ack;
                    tcp_set_state(sk, TCP_ESTABLISHED);
                    if (sk->parent != NULL)
                        fnp_ring_enqueue(sk->parent->accept, sk);
                } else {
                    tcp_send_rst(seg);
                    return;  //不确定是否drop
                }
            } else {    //recv retransmission syn
                tcp_timer_stop(sk, TCPT_REXMT);
                sk->snd_nxt = sk->snd_una;      //立即重传
            }
        } else {    //recv a new syn again
            tcp_set_state(sk, TCP_CLOSED);
            tcp_free_sock(sk);
        }
        return;
    }

    if (seg_set_ack(seg)) {      //check ACK
        if (sk->snd_nxt == seg->ack) {      //reach here only set ACK
            sk->snd_una = seg->ack;
            if(sk->snd_una == sk->snd_max) {
                tcp_timer_stop(sk, TCPT_REXMT);
            }
            sk->adv_wnd = seg->rx_win;
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
            tcp_set_state(sk, TCP_ESTABLISHED);
            if (sk->parent != NULL)
                fnp_ring_enqueue(sk->parent->accept, sk);
            tcp_handle_data(sk, seg);
        } else {
            tcp_send_rst(seg);
        }
    }
}

void tcp_default_handle(tcp_sock_t* sk, tcp_seg_t* seg)  {
    if(!acceptable_seq(sk, seg)) {   //check whether seq is valid
        if(!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return;
    }

    //rcv_nxt <= seq
    if(seg_set_rst(seg)) {                  //check RST
        if(sk->rcv_nxt == seg->seq) {
            tcp_set_state(sk, TCP_CLOSED);
            tcp_free_sock(sk);
        } else {    //rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    if(seg_set_syn(seg)) {                      //check SYN
        tcp_send_ack(sk, false);
        return;
    }

    if(seg_set_ack(seg)) {      //check ACK
        tcp_handle_ack(sk, seg);
    } else {    //没有ACK就直接丢弃
        return ;
    }

    //check the URG
//    if(seg_set_urg(seg)) {
//        if(sk->state == TCP_ESTABLISHED ||
//           sk->state == TCP_FIN_WAIT_1 || sk->state == TCP_FIN_WAIT_2) {
//                    sk->snd_up = seg;
//        }
//    }

    //recv data
    tcp_handle_data(sk, seg);

    //check the FIN
    if(seg_set_fin(seg)) {
        sk->rcv_nxt = seg->seq + 1;
        tcp_send_ack(sk, false);
        switch (sk->state) {
            case TCP_SYN_RECV:
            case TCP_ESTABLISHED: {
                tcp_set_state(sk, TCP_CLOSE_WAIT);
                break;
            }
            case TCP_FIN_WAIT_1: {
                tcp_set_state(sk, TCP_CLOSING);
                break;
            }
            case TCP_FIN_WAIT_2: {
                tcp_set_state(sk, TCP_TIME_WAIT);
                tcp_timer_start(sk, TCPT_2MSL);
                break;
            }
        }
    }
}

void tcp_recv_mbuf(rte_mbuf* m)
{
    tcp_sock_t* sk = NULL;
    tcp_seg_t seg;
    tcp_seg_init(m, &seg);

    if(unlikely(!tcp_lookup_sock(&seg, &sk) || tcp_state(sk) == TCP_CLOSED)) {  //没有该连接
        printf("no socket or socket is CLOSED\n");
        if(!seg_set_rst(&seg))     //不是RST包
            tcp_send_rst(&seg);
        fnp_free_mbuf(m);
        return ;
    }

    i32 state = tcp_state(sk);
    switch (state) {
        case TCP_LISTEN: {
            tcp_listen_handle(sk, &seg);
            break;
        }
        case TCP_SYN_SENT: {
            tcp_syn_sent_handle(sk, &seg);
            break;
        }
        case TCP_SYN_RECV: {
            tcp_syn_recv_handle(sk, &seg);
            break;
        }
        default: {
            tcp_default_handle(sk, &seg);
        }
    }

    fnp_free_mbuf(m);
}
