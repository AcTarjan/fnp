#ifndef FNP_TCP_TIMER_H
#define FNP_TCP_TIMER_H

#include "fnp_common.h"
#include <rte_timer.h>
#include "fnp_tcp.h"

static inline bool tcp_timer_is_running(tcp_sock_t* sk, i32 index) {
    return rte_timer_pending(&sk->timers[index]);
}

static inline void tcp_timer_stop(tcp_sock_t* sk, i32 index) {
    if(index == TCPT_REXMT)
        sk->retransmission_num = 0;
    rte_timer_stop(&sk->timers[index]);
}

void tcp_timer_start(tcp_sock_t* sk, i32 index);

void tcp_timer_stop(tcp_sock_t* sk, i32 index);

#endif //FNP_TCP_TIMER_H
