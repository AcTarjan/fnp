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
#define TCP_USER_FREE   0x04

#define TCP_LISTEN_BACKLOG 128



typedef struct tcp_option {
    u8 wnd_scale;
    u8 permit_sack;
    u16 mss;
    struct {
        u32 ts_val;
        u32 ts_ecr;
    } ts;
} tcp_option;


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
    tcp_option opt;
    u8* data;
} tcp_segment;

typedef struct tcp_sock {
    struct tcp_sock* parent;
    sock_param* param;
    fnp_iface* iface;
    i32 state;
    u32 user_req;               //tcp connect

    bool can_free;           //进入accept队列后，和被用户使用后，不能释放

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
} tcp_sock;

typedef void (*tcp_recv_func)(tcp_sock* sk, tcp_segment* seg);
typedef void (*tcp_send_func)(tcp_sock* sk);

extern tcp_recv_func tcp_recv[TCP_STATE_END];
extern tcp_send_func tcp_send[TCP_STATE_END];

inline static i32 tcp_state(tcp_sock* sk)
{
    return sk->state;
}


void tcp_set_state(tcp_sock* sk, i32 state);

void* tcp_bind(sock_param* param);
void* tcp_listen(sock_param* param);
void* tcp_connect(sock_param* param);
void tcp_free_sock(void* sock);

#endif //FNP_TCP_SOCK_H
