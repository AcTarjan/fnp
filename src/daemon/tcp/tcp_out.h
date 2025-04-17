#ifndef FNP_TCP_OUT_H
#define FNP_TCP_OUT_H

#include "tcp_sock.h"

typedef void (*tcp_send_func)(tcp_sock_t *sk);

void tcp_send_ack(tcp_sock_t *sock, bool delay);

void tcp_send_rst(tcp_segment *seg);

void tcp_empty_send(tcp_sock_t *sock);

void tcp_data_send(tcp_sock_t *sock);

void tcp_syn_send(tcp_sock_t *sock);

void tcp_closed_send(tcp_sock_t *sock);

// snd_nxt变为snd_una，然后从snd_nxt开始发送数据
// 问题：触发重传后，然后收到ack，导致snd_una比snd_nxt大
// 解决方案：目前通过将定时器触发，放在socket_output前，snd_nxt修改后就立刻重传，避免收到ack。
static inline void tcp_retransmit(tcp_sock_t *sock)
{
    sock->retransmission_num++;
    printf("the num of retransmission: %d\n", sock->retransmission_num);
    if (sock->retransmission_num > 6)
    {
        printf("retransmission failed!\n");
        tcp_set_state(sock, TCP_CLOSED);
        return;
    }

    sock->snd_nxt = sock->snd_una; // 重传数据
    sock->fin_sent = 0;            // 重传FIN
    sock->cwnd = 1;                // 减小发送窗口
}

#endif // FNP_TCP_OUT_H
