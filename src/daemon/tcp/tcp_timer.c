#include "tcp_timer.h"
#include "tcp_sock.h"
#include "tcp_out.h"


// 当发送数据时，如果重传定时器没有启动，则启动重传定时器
// 当接收到ack时, 停止重传定时器。如果还有未确认的数据，则重启重传定时器
void tcp_retransmit_callback(__attribute__((unused)) struct rte_timer* tim, void* arg)
{
    tcp_sock_t* sock = arg;
    sock->is_retransmitting_timer = 0;
    sock->retransmission_count++;
    if (unlikely(sock->retransmission_count > 5))
    {
        tcp_set_state(sock, TCP_CLOSED);
        return;
    }

    // 开始重传
    tcp_state_t state = tcp_get_state(sock);
    if (unlikely(state == TCP_SYN_SENT || state == TCP_SYN_RECV))
        tcp_send_syn(sock);
    else
    {
        // 更新拥塞控制算法
        // sock->cc_algo.notify(&sock->cc_algo, congestion_notification_timeout, 0, 0);
        tcp_start_retransmit(sock);
    }
}

void tcp_start_retransmit_timer(tcp_sock_t* sock)
{
    if (likely(sock->is_retransmitting_timer))
    {
        return;
    }
    sock->is_retransmitting_timer = 1;
    u64 hz = rte_get_timer_hz(); // 定时器的频率
    u32 lcore_id = rte_lcore_id();

    if (unlikely(rte_timer_reset(&sock->retransmit_timer, (sock->retransmission_count + 1) * hz, SINGLE, lcore_id,
        tcp_retransmit_callback, sock) != 0))
    {
        printf("fail to reset timer of retransmission: %u\n", sock->retransmit_timer.status.state);
    }
}


void delay_ack_callback(__attribute__((unused)) struct rte_timer* tim, void* arg)
{
    tcp_sock_t* sock = arg;
    sock->is_delaying_ack = 0;
    tcp_send_ack(sock, false);
}


void tcp_start_ack_timer(tcp_sock_t* sock)
{
    if (likely(sock->is_delaying_ack))
        return;
    sock->is_delaying_ack = 1;
    u64 hz = rte_get_timer_hz(); // 定时器的频率
    u32 lcore_id = rte_lcore_id();

    if (unlikely(rte_timer_reset(&sock->ack_timer, hz / 200, SINGLE, lcore_id,
        delay_ack_callback, sock) != 0))
    {
        printf("fail to reset timer of delay ack\n");
    }
}


void timeout_2msl_callback(__attribute__((unused)) struct rte_timer* tim, void* arg)
{
    tcp_sock_t* sock = arg;
    tcp_set_state(sock, TCP_CLOSED);
}

void tcp_start_2msl_timer(tcp_sock_t* sock)
{
    u64 hz = rte_get_timer_hz(); // 定时器的频率
    u32 lcore_id = rte_lcore_id();

    if (unlikely(rte_timer_reset(&sock->msl_timer, hz * 2, SINGLE, lcore_id,
        timeout_2msl_callback, sock) != 0))
    {
        printf("fail to reset timer of 2msl\n");
    }
}
