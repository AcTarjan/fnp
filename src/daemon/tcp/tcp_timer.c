#include "tcp_timer.h"
#include "tcp_sock.h"
#include "tcp_out.h"

// 当发送数据时，如果重传定时器没有启动，则启动重传定时器
// 当接收到ack时, 停止重传定时器。如果还有未确认的数据，则重启重传定时器
void retransmission_callback(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    tcp_sock_t *sock = arg;
    tcp_retransmit(sock);
}

void delay_ack_callback(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    tcp_sock_t *sk = arg;
    tcp_send_ack(sk, false);
}

void timeout_2msl_callback(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    tcp_sock_t *sock = arg;
    printf("timeout_2msl_callback");
    tcp_set_state(sock, TCP_CLOSED);
}

void tcp_timer_start(tcp_sock_t *sk, i32 index)
{
    u64 hz = rte_get_timer_hz(); // 定时器的频率
    u32 lcore_id = rte_lcore_id();

    switch (index)
    {
    case TCPT_REXMT:
    {
        if (unlikely(rte_timer_reset(&sk->timers[TCPT_REXMT], hz, SINGLE, lcore_id,
                                     retransmission_callback, sk) != 0))
        {
            printf("fail to reset timer of retransmission: %u\n", sk->timers[TCPT_REXMT].status.state);
        }
        break;
    }
    case TCPT_DELAY_ACK:
    {
        if (unlikely(rte_timer_reset(&sk->timers[TCPT_DELAY_ACK], hz / 200, SINGLE, lcore_id,
                                     delay_ack_callback, sk) != 0))
        {
            printf("fail to reset timer of delay ack\n");
        }
        break;
    }
    case TCPT_2MSL:
    {
        if (unlikely(rte_timer_reset(&sk->timers[TCPT_2MSL], hz * 2, SINGLE, lcore_id,
                                     timeout_2msl_callback, sk) != 0))
        {
            printf("fail to reset timer of 2msl\n");
        }
        break;
    }
    }
}
