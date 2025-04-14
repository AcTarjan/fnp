#ifndef FNP_TCP_SOCK_H
#define FNP_TCP_SOCK_H

#include "fnp_pring.h"
#include "fnp_socket.h"
#include "tcp_comm.h"
#include "rbtree.h"

#include <rte_timer.h>

// 用来表示一个TCP Connection
typedef struct tcp_sock
{
    fnp_socket_t socket;
    struct tcp_sock *parent;

    i32 state;

    // 发送相关
    u32 iss;          // 初始的发送序号
    u32 snd_una;      // 已发送为确认的序号
    u32 snd_nxt;      // 下一个发送的序号
    u32 snd_max;      // 已发送的最大序号，区别重传
    u32 snd_wnd;      // 发送窗口，min(adv_wnd, cwnd)
    u32 cwnd;         // 拥塞窗口
    u32 adv_wnd;      // 接收方的接收窗口
    u32 max_snd_wnd;  // max(snd_wnd, max_snd_wnd)
    u32 snd_wl1;      // SND.WL1 records the sequence number of the last segment used to update SND.WND
    u32 snd_wl2;      // SND.WL2 records the acknowledgment number of the last segment used to update SND.WND
    u16 snd_up;       // urgent pointer
    u8 snd_wnd_scale; // 发送窗口的缩放因子, 即对方的接收窗口的缩放因子
    u8 fin_sent;      // 是否发送过FIN，避免重复发送
    fnp_pring *txbuf; // 重传队列

    // 接收相关
    u8 rcv_wnd_scale; // 接收窗口的缩放因子, 即自己的接收窗口的缩放因子
    u32 irs;          // 接收到的初始序号
    u32 rcv_nxt;      // 下一个接收的序号
    u32 rcv_wnd;      // 接收窗口

    i16 dup_ack;            // 快重传，收到重复的ack数目
    i16 retransmission_num; // 重传次数
    bool permit_sack;
    u16 mss; // maximum segment size, 对方的mss和自己的mss取最小值

    i32 tx_offset;
    rb_tree ofo_root; // 乱序队列

    struct rte_timer timers[TCPT_NTIMERS];
} tcp_sock_t;

#define tcp_get_state(sock) ((sock)->state)
void tcp_set_state(tcp_sock_t *sock, i32 state);

tcp_sock_t *create_tcp_sock();

void free_tcp_sock(tcp_sock_t *sock);

#endif // FNP_TCP_SOCK_H
