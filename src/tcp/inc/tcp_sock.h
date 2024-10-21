#ifndef FNP_TCP_SOCK_H
#define FNP_TCP_SOCK_H

#include <semaphore.h>
#include "fnp_init.h"

#include "fnp_ring.h"
#include "fnp_init.h"
#include "tcp_comm.h"
#include "rbtree.h"

#include <rte_tcp.h>

#define TCP_USER_CONNECT   0x01
#define TCP_USER_CLOSE   0x02

#define TCP_LISTEN_BACKLOG 128



typedef struct tcp_option {
    u8 wnd_scale;
    u8 permit_sack;
    u16 mss;
    struct {
        u32 ts_val;
        u32 ts_ecr;
    } ts;
} tcp_option_t;


typedef struct tcp_segment
{
    u32 lip;
    u32 rip;
    u16 lport;
    u16 rport;
    u32 seq;
    u32 ack;
    u32 rx_win;
    u16 data_len;
    u16 iface_id;
    u8 hdr_len;
    u8 flags;
    tcp_option_t opt;
    u8* data;
} tcp_seg_t;


typedef struct tcp_sock_key {
    u32 id;
    u32 rip;
    u16 port;
    u16 rport;
} tcp_sock_key_t;

typedef struct tcp_sock {
    struct tcp_sock* parent;
    union {
        tcp_sock_key_t key;
        struct {
            u32 id;
            u32 rip;
            u16 port;
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
    u8 snd_wnd_scale;           // 发送窗口的缩放因子, 即对方的接收窗口的缩放因子
    u8  rcv_wnd_scale;          // 接收窗口的缩放因子, 即自己的接收窗口的缩放因子


    u32 irs;                    // initial recving sequence number
    u32 rcv_nxt;                // receive next
    u32 rcv_wnd;                // the size of receiving window

    //快重传
    i16 dup_ack;                //收到重复的ack数目
    i16 retransmission_num;     //重传次数

    u16 mss;                        //maximum segment size, 对方的mss和自己的mss取最小值

    u32 user_req;               //tcp connect
    union {
        fnp_pring* accept;
        struct {
            fnp_ring* txbuf;
            fnp_ring* rxbuf;
        };
    };

    void (*tcp_send)(struct tcp_sock* sk);
    void (*tcp_recv)(struct tcp_sock* sk, tcp_seg_t* seg);


    rb_tree ofo_root;

    struct rte_timer timers[TCPT_NTIMERS];
} tcp_sock_t;


inline static i32 tcp_state(tcp_sock_t* sk)
{
    return sk->state;
}


void tcp_set_state(tcp_sock_t* sk, i32 state);


static inline bool tcp_can_send(tcp_sock_t *sk) {
   u32 state = tcp_state(sk);
   if (state == TCP_ESTABLISHED || state == TCP_CLOSE_WAIT) {
       if (fnp_ring_avail(sk->txbuf) == 0) //发送缓冲区满
           return false;
       return true;
   }
   return false;
}

static inline bool tcp_still_recv(tcp_sock_t* sk) {
    i32 state = tcp_state(sk);
    if(state == TCP_ESTABLISHED ||
       state == TCP_FIN_WAIT_1 ||
       state == TCP_FIN_WAIT_2 ) {  //可以接收数据
        return true;
    }

    if(fnp_ring_len(sk->rxbuf) > 0) {
        return true;
    }

    return false;
}

void* fnp_tcp_sock(u32 id, u16 port, u32 rip, u16 rport);

i32 fnp_lookup_sock(tcp_sock_key_t* key, tcp_sock_t** sk);

#endif //FNP_TCP_SOCK_H
