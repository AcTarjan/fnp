#ifndef TCP_TIMER_H
#define TCP_TIMER_H

#include <rte_timer.h>
#include "tcp_sock.h"

static inline void tcp_stop_retransmit_timer(tcp_sock_t* sock)
{
    sock->is_retransmitting_timer = 0;
    sock->retransmission_count = 0;
    rte_timer_stop(&sock->retransmit_timer);
}

void tcp_start_retransmit_timer(tcp_sock_t* sock);

void tcp_start_ack_timer(tcp_sock_t* sock);

static inline void tcp_stop_ack_timer(tcp_sock_t* sock)
{
    sock->is_delaying_ack = 0;
    rte_timer_stop(&sock->ack_timer);
}

void tcp_start_2msl_timer(tcp_sock_t* sock);

static inline void tcp_stop_2msl_timer(tcp_sock_t* sock)
{
    rte_timer_stop(&sock->msl_timer);
}

#endif //TCP_TIMER_H
