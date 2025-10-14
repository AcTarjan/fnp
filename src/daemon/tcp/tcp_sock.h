#ifndef FNP_TCP_SOCK_H
#define FNP_TCP_SOCK_H

#include "fnp_ring.h"
#include "fsocket.h"
#include "tcp_comm.h"
#include "fnp_splay.h"
#include "fnp_list.h"
#include "fnp_cc.h"

#include <rte_timer.h>

typedef struct tcp_mbufinfo
{
    u32 seq; // 发送的序号
    i32 len; // 发送的长度
    fnp_list_node_t node; // pending list
    u8 flags;
} tcp_mbufinfo_t;

#define get_tcp_mbufinfo(m) ((tcp_mbufinfo_t *)rte_mbuf_to_priv(m));

// 用来表示一个TCP Connection
typedef struct tcp_sock
{
    fsocket_t socket;
    struct tcp_sock* parent;

    tcp_state_t state;

    // 发送相关
    congestion_algorithm_t cc_algo; // 拥塞控制算法
    u32 iss; // 初始的发送序号
    u32 snd_una; // 已发送为确认的序号
    u32 snd_nxt; // 下一个发送的序号, 始终递增
    // u32 snd_max; // 已发送的最大序号，区别重传
    u32 adv_wnd; // 接收方的接收窗口
    u32 max_snd_wnd; // max(snd_wnd, max_snd_wnd)
    u32 snd_wl1; // SND.WL1 records the sequence number of the last segment used to update SND.WND
    u32 snd_wl2; // SND.WL2 records the acknowledgment number of the last segment used to update SND.WND
    u32 retransmitting_seq;
    u16 snd_up; // urgent pointer
    u8 snd_wnd_scale; // 发送窗口的缩放因子, 即对方的接收窗口的缩放因子
    u8 retransmission_count;
    fnp_list_t pending_list; // 待确认的队列, 根据数据包seq排序，仅第一个数据包的tsc有效。

    // 接收相关
    u32 irs; // 接收到的初始序号
    u32 rcv_nxt; // 下一个接收的序号
    u32 rcv_wnd; // 接收窗口
    u8 rcv_wnd_scale; // 接收窗口的缩放因子, 即自己的接收窗口的缩放因子
    i8 dup_ack; // 快重传，收到重复的ack数目
    u16 mss; // maximum segment size, 对方的mss和自己的mss取最小值
    picosplay_tree_t ofo_tree;

    u32 permit_sack : 1;
    u32 is_retransmitting : 1; // 是否重传中
    u32 is_retransmitting_timer : 1; // 重传定时器是否正在运行
    u32 is_delaying_ack : 1; // 是否正在延迟ACK
    u32 fin_sent : 1; // 是否重传中
    u32 fin_received : 1; // 是否接收到FIN

    struct rte_timer retransmit_timer; //重传定时器
    struct rte_timer ack_timer; // 延迟ACK定时器
    struct rte_timer msl_timer; // 2MSL定时器
} tcp_sock_t;

#define tcp_get_state(sock) ((sock)->state)
void tcp_set_state(tcp_sock_t* sock, tcp_state_t state);

static inline tcp_mbufinfo_t* node_to_tcp_mbufinfo(fnp_list_node_t* node)
{
    return node == NULL ? NULL : get_tcp_mbufinfo(node->value);
}

tcp_sock_t* tcp_create_sock(fsockaddr_t* local, fsockaddr_t* remote, void* conf);

void free_tcp_sock(tcp_sock_t* sock);

#endif // FNP_TCP_SOCK_H
