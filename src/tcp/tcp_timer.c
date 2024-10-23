#include "tcp_timer.h"
#include "tcp_sock.h"
#include "tcp_out.h"

//当发送数据时，如果重传定时器没有启动，则启动重传定时器
//当接收到ack时, 停止重传定时器。如果还有未确认的数据，则重启重传定时器
void retransmission_callback(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    tcp_sock* sk = arg;
    sk->retransmission_num ++;
    if(sk->retransmission_num > 6) {
        printf("retransmission failed!: %d\n", sk->retransmission_num);
        tcp_set_state(sk, TCP_CLOSED);
        rte_timer_stop(tim);        //停止
        return;
    }
    printf("retransmission_callback: %d\n", sk->retransmission_num);
    sk->snd_nxt = sk->snd_una;
    sk->cwnd = 1;           //减小发送窗口
}


void delay_ack_callback(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    tcp_sock* sk = arg;
    tcp_send_ack(sk, false);
}

void timeout_2msl_callback(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    tcp_sock* sk = arg;
    printf("timeout_2msl_callback");
    tcp_set_state(sk, TCP_CLOSED);
}

void tcp_timer_start(tcp_sock* sk, i32 index) {
    u64 hz = rte_get_timer_hz();    //定时器的频率
    u32 lcore_id = rte_lcore_id();

    switch (index) {
        case TCPT_REXMT: {
            if(unlikely(rte_timer_reset(&sk->timers[TCPT_REXMT], hz, PERIODICAL, lcore_id,
                            retransmission_callback, sk) != 0)) {
                printf("fail to reset timer of retransmission: %u\n", sk->timers[TCPT_REXMT].status.state);
            }
            break;
        }
        case TCPT_DELAY_ACK: {
            if(unlikely(rte_timer_reset(&sk->timers[TCPT_DELAY_ACK], hz / 200, SINGLE, lcore_id,
                                        delay_ack_callback, sk) != 0)) {
                printf("fail to reset timer of delay ack\n");
            }
            break;
        }
        case TCPT_2MSL: {
            if(unlikely(rte_timer_reset(&sk->timers[TCPT_2MSL], hz * 2, SINGLE, lcore_id,
                                        timeout_2msl_callback, sk) != 0)) {
                printf("fail to reset timer of 2msl\n");
            }
            break;
        }
    }
}



