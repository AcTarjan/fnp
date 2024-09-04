#ifndef FNP_FNP_TCP_SOCK_H
#define FNP_FNP_TCP_SOCK_H

#include <semaphore.h>
#include "fnp_init.h"

#include "fnp_ring.h"
#include "fnp_init.h"
#include "fnp_tcp_comm.h"
#include "fnp_tcp_ofo.h"
#include <rte_tcp.h>

#define TCP_USER_CONNECT   0x01
#define TCP_USER_CLOSE   0x02

typedef struct tcp_sock_key {
    u32 lip;
    u32 rip;
    u16 lport;
    u16 rport;
} tcp_sock_key_t;

typedef struct tcp_sock {
    struct tcp_sock* parent;
    fnp_iface_t* iface;
    union {
        tcp_sock_key_t key;
        struct {
            u32 lip;
            u32 rip;
            u16 lport;
            u16 rport;
        };
    };

    i32 state;

    u32 iss;                // initial sending sequence number
    u32 snd_una;            // send unacknowledged
    u32 snd_nxt;            // send next
    u32 snd_max;                //to identify retransmission
    u32 snd_wnd;                // min(adv_wnd, cwnd)
    u32 cwnd;                   // 拥塞窗口
    u32 adv_wnd;                // 接收方的接收窗口
    u32 max_snd_wnd;            // max(snd_wnd, max_snd_wnd)
    u32 snd_wl1;                // SND.WL1 records the sequence number of the last segment used to update SND.WND
    u32 snd_wl2;                // SND.WL2 records the acknowledgment number of the last segment used to update SND.WND
    u16 snd_up;                 // urgent pointer

    u32 irs;                    // initial recving sequence number
    u32 rcv_nxt;                // receive next
    u32 rcv_wnd;                // the size of receiving window

    //快重传
    i16 dup_ack;                //收到重复的ack数目
    i16 retransmission_num;     //重传次数

    u16 mss;                    //max segment size

    fnp_ring_t* accept;         //tcp listen
    u32 user_req;               //tcp connect
    fnp_ring_t* txbuf;
    fnp_ring_t* rxbuf;
    struct tcp_ofo_segment* ofo_head;

    struct rte_timer timers[TCPT_NTIMERS];
} tcp_sock_t;

inline static i32 tcp_state(tcp_sock_t* sk)
{
    return sk->state;
}


inline static void tcp_set_state(tcp_sock_t* sk, i32 state)
{
    i32 old_state = tcp_state(sk);
    sk->state = state;
//    rte_atomic32_set(&sk->state, state);
    printf("state from %s to %s\n",
           tcp_state_str[old_state], tcp_state_str[state]);
}


static inline bool tcp_can_send(tcp_sock_t *sk) {
   u32 state = tcp_state(sk);
   if (state == TCP_ESTABLISHED || state == TCP_CLOSE_WAIT) {
       if (fnp_ring_avail(sk->txbuf) == 0) //发送缓冲区满
           return false;
       return true;
   }
   return false;
}

static inline bool tcp_can_recv(tcp_sock_t* sk) {
    i32 state = tcp_state(sk);
    if(state == TCP_ESTABLISHED ||
       state == TCP_FIN_WAIT_1 ||
       state == TCP_FIN_WAIT_2 ) {  //可以接收数据
        return true;
    }
    if (state == TCP_CLOSE_WAIT ||
    state == TCP_CLOSING ||
    state == TCP_LAST_ACK ||
    state == TCP_TIME_WAIT) { //收到了对方发送了FIN, 把缓冲区的数据收完
        if (fnp_ring_len(sk->rxbuf) != 0 || !tcp_ofo_is_empty(sk->ofo_head))
            return true;
    }
    return false;
}

void* fnp_tcp_sock(u32 lip, u16 lport, u32 rip, u16 rport);

void tcp_free_sock(void* sock);

#endif //FNP_FNP_TCP_SOCK_H
