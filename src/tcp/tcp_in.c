#include "fnp_init.h"
#include "tcp_comm.h"
#include "tcp_sock.h"
#include "tcp_ofo.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_timer.h"
#include <unistd.h>
#include <rte_tcp.h>


static inline void tcp_handle_syn_option(tcp_sock_t* sk, tcp_segment* seg) {
    if (seg_has_opt(seg)) {
        if (unlikely(seg_set_syn(seg))) {
            if (seg->opt.mss != 0) {    //支持MSS选项
                sk->mss = FNP_MIN(sk->mss, seg->opt.mss);
            }

            if (seg->opt.wnd_scale != 255) {    //支持窗口扩展
                sk->snd_wnd_scale = seg->opt.wnd_scale;
            } else {
                sk->snd_wnd_scale = 0;
                sk->rcv_wnd_scale = 0;
            }

            sk->permit_sack = true;
        }
    }
}

static inline u8 acceptable_seq(tcp_sock_t* sk, tcp_segment* cb)
{
    // 必须所有字节都在接收窗口内
    if(unlikely(cb->data_len == 0))
        return SEQ_LE(sk->rcv_nxt, cb->seq) && SEQ_LT(cb->seq, sk->rcv_nxt + sk->rcv_wnd);

    const u32 end_seq = cb->seq + cb->data_len - 1;
    return (SEQ_LE(sk->rcv_nxt, cb->seq) && SEQ_LT(cb->seq, sk->rcv_nxt + sk->rcv_wnd)) &&
           (SEQ_LE(sk->rcv_nxt, end_seq) && SEQ_LT(end_seq, sk->rcv_nxt + sk->rcv_wnd));
}

static inline void tcp_handle_in_order_data(tcp_sock_t* sk, tcp_segment* seg) {
    i32 state = tcp_state(sk);
    if(likely(seg->data_len > 0 && (state == TCP_ESTABLISHED ||
        state == TCP_FIN_WAIT_1))) {
        i32 rx_len = fnp_ring_push(sk->rxbuf, seg->data, seg->data_len);
        sk->rcv_nxt += rx_len;
        if (rx_len > 0) {
            //check out of order
            u32 rcv_nxt = sk->rcv_nxt;
            seg->flags |= tcp_ofo_dequeue(&sk->ofo_root, &sk->rcv_nxt);
            fnp_ring_push_empty(sk->rxbuf, (i32)(sk->rcv_nxt - rcv_nxt));
        }
        tcp_send_ack(sk, true);
    }
}

static inline void tcp_handle_ack(tcp_sock_t* sk, tcp_segment* seg) {
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

static inline void tcp_handle_data(tcp_sock_t* sk, tcp_segment* seg) {
    if (sk->rcv_nxt == seg->seq) {
        tcp_handle_in_order_data(sk, seg);
        return;
    }
    // 乱序的数据包，先不处理FIN
    tcp_ofo_seg* ofo_seg = tcp_ofo_malloc(seg->seq, seg->data_len, seg->flags);
    seg->flags &= ~RTE_TCP_FIN_FLAG;    //去掉FIN标志，已经保存了
    u32 seq = tcp_ofo_enqueue(&sk->ofo_root, ofo_seg);
    u32 rx_offset = seq - sk->rcv_nxt;
    u32 data_offset = seq - seg->seq;
    if (data_offset < seg->data_len)
        fnp_ring_prepush(sk->rxbuf, (i32)rx_offset, seg->data + data_offset, seg->data_len - (i32)data_offset);
    tcp_send_ack(sk, false);         //收到乱序的数据，立即回ACK
}

static inline void tcp_handle_fin(tcp_sock_t* sk, tcp_segment* seg) {
    if (seg_set_fin(seg)) {
        sk->rcv_nxt++;      //FIN占用一个序列号
        tcp_send_ack(sk, false);
        switch (sk->state) {
            case TCP_SYN_RECV:
            case TCP_ESTABLISHED: {     //
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

// 收到重传的SYN
// 收到SYN|ACK
// 收到ACK
// 收到数据包（可能乱序），对方已经是ESTABLISHED状态
void tcp_synrecv_recv(tcp_sock_t* sk, tcp_segment* seg) {
    if (!acceptable_seq(sk, seg) && seg->seq != sk->irs) {
        if (!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return ;
    }

    if (seg_set_rst(seg)) {                  //check RST
        if (sk->rcv_nxt == seg->seq) {
            tcp_set_state(sk, TCP_CLOSED);
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
                    tcp_handle_syn_option(sk, seg);
                    tcp_set_state(sk, TCP_ESTABLISHED);
                    if (sk->parent != NULL) {
                        sk->can_free = false;
                        fnp_pring_enqueue(sk->parent->accept, sk);
                    }
                } else {
                    tcp_send_rst(seg);
                    return;  //不确定是否drop
                }
            } else {    //recv retransmission syn
                tcp_handle_syn_option(sk, seg);
                tcp_timer_stop(sk, TCPT_REXMT);
                sk->snd_nxt = sk->snd_una;      //立即重传
            }
        } else {    //recv a new syn again
            tcp_set_state(sk, TCP_CLOSED);
        }
        return;
    }

    if (seg_set_ack(seg)) {      //check ACK
        if (seg->ack == sk->snd_max) {      //reach here only set ACK
            sk->snd_una = seg->ack;
            sk->adv_wnd = seg->rx_win;
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
            tcp_timer_stop(sk, TCPT_REXMT);
            tcp_set_state(sk, TCP_ESTABLISHED);
            if (sk->parent != NULL) {
                sk->can_free = false;
                fnp_pring_enqueue(sk->parent->accept, sk);
            }
            // 处理数据
            tcp_handle_data(sk, seg);
        } else {
            tcp_send_rst(seg);
        }
    }
}

void tcp_listen_recv(tcp_sock_t* sk, tcp_segment* seg)  {
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
        sock_t* sock = sock_create(IPPROTO_TCP, seg->lip, seg->lport, seg->rip, seg->rport);
        tcp_sock_t *newsk = (tcp_sock_t*) sock;
        if (newsk == NULL) {
            tcp_send_rst(seg);
            printf("fail to new a tcp_sock\n");
            return;
        }
        newsk->parent = sk;

        newsk->irs = seg->seq;
        newsk->adv_wnd = seg->rx_win;
        newsk->rcv_nxt = seg->seq + 1;

        tcp_handle_syn_option(newsk, seg);

        tcp_set_state(newsk, TCP_SYN_RECV);
    }

}

void tcp_synsent_recv(tcp_sock_t* sk, tcp_segment* seg)  {
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
        }
        return;
    }

    //check the security

    //reach here only if the ACK is ok, or there is no ACK, and the segment did not contain an RST.
    if(seg_set_syn(seg)) {
        sk->irs = seg->seq;
        sk->rcv_nxt = seg->seq + 1;

        if(seg_set_ack(seg)) {  //recv SYN|ACK, 正常流程
            sk->snd_una = seg->ack;
            sk->adv_wnd = seg->rx_win;  //更新发送窗口
            sk->snd_wl1 = seg->seq;
            sk->snd_wl2 = seg->ack;
            tcp_handle_syn_option(sk, seg);
            tcp_timer_stop(sk, TCPT_REXMT);     //收到了对自己SYN的ack，停止重传计时器
            tcp_set_state(sk, TCP_ESTABLISHED);
            tcp_send_ack(sk, false);            //立即发送对对方SYN的ack
            if(sk->parent != NULL) {
                sk->can_free = false;
                fnp_pring_enqueue(sk->parent->accept, sk);
            }
            return;
        }

        // 只收到SYN, 适合同时发送SYN的情况
        tcp_handle_syn_option(sk, seg);
        tcp_set_state(sk, TCP_SYN_RECV);
        tcp_timer_stop(sk, TCPT_REXMT);
        sk->snd_nxt = sk->snd_una;      //已经发送过SYN了，后面需要发送SYN|ACK
    }
}

void tcp_estab_recv(tcp_sock_t* sk, tcp_segment* seg)  {
    if(!acceptable_seq(sk, seg)) {
        if(!seg_set_rst(seg))
            tcp_send_ack(sk, false);
        return;
    }

    //seq >= rcv_nxt
    if(seg_set_rst(seg)) {                  //check RST
        if(sk->rcv_nxt == seg->seq) {
            tcp_set_state(sk, TCP_CLOSED);
        } else {    //rcv_nxt <  seq <= rcv_nxt + rcv_wnd
            tcp_send_ack(sk, false);
        }
        return;
    }

    //check SYN
    if(seg_set_syn(seg)) {
        tcp_send_ack(sk, false);
        return;
    }

    //check ACK
    if(seg_set_ack(seg)) {
        tcp_handle_ack(sk, seg);
    } else {    //没有ACK就直接丢弃
        return ;
    }

    //recv data
    tcp_handle_data(sk, seg);

    //check the FIN
    tcp_handle_fin(sk, seg);
}

void tcp_closed_recv(tcp_sock_t* sk, tcp_segment* seg) {}
