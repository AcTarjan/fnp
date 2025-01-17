#ifndef FNP_TCP_SOCK_H
#define FNP_TCP_SOCK_H

#include "fnp_ring.h"
#include "fnp_init.h"
#include "tcp_comm.h"
#include "rbtree.h"


#include "fnp_sock.h"

typedef struct tcp_sock {
    sock_t sock;
    struct tcp_sock* parent;
    fnp_iface_t* iface;
    i32 state;
    u32 user_req;               //tcp connect

    bool can_free;           //进入accept队列后，和被用户使用后，不能释放
    bool permit_sack;
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

    union {
        fnp_pring* accept;
        struct {
            fnp_ring* txbuf;
            fnp_ring* rxbuf;
        };
    };

    rb_tree ofo_root;

    struct rte_timer timers[TCPT_NTIMERS];
} tcp_sock_t;

#define tcp_state(sk)  ((sk)->state)
void tcp_set_state(tcp_sock_t* sk, i32 state);

tcp_sock_t* tcp_sock_ipv4(ipv4_5tuple_t* key);


void tcp_free_sock(tcp_sock_t* sock);


#endif //FNP_TCP_SOCK_H
