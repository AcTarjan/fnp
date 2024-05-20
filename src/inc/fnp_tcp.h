#ifndef FNP_TCP_H
#define FNP_TCP_H

#include <stdio.h>
#include <semaphore.h>

#include "fnp_ring.h"
#include "fnp_init.h"
#include <rte_tcp.h>

#define TCP_HDR_MIN_LEN             20
#define TCP_MAX_SEG_SIZE             1460

#define	TCPT_NTIMERS	5
#define	TCPT_REXMT	0		    /* retransmit */
#define	TCPT_PERSIST	1		/* retransmit persistance */
#define	TCPT_DELAY_ACK	2		/* delay ack */
#define	TCPT_KEEP	3	        /* keep alive */
#define	TCPT_2MSL	4		    /* 2*msl quiet time timer */

#define TCP_MIN_CWND            2
#define TCP_MAX_CWND            1024
#define TCP_THRESHOLD           32


typedef struct tcp_sock_key {
    u32 lip;
    u32 rip;
    u16 lport;
    u16 rport;
} tcp_sock_key_t;

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

#define seg_set_rst(seg)   ((seg)->flags & RTE_TCP_RST_FLAG)
#define seg_set_ack(seg)   ((seg)->flags & RTE_TCP_ACK_FLAG)
#define seg_set_syn(seg)   ((seg)->flags & RTE_TCP_SYN_FLAG)
#define seg_set_fin(seg)   ((seg)->flags & RTE_TCP_FIN_FLAG)
#define seg_set_urg(seg)   ((seg)->flags & RTE_TCP_URG_FLAG)
#define seg_set_psh(seg)   ((seg)->flags & RTE_TCP_PSH_FLAG)
#define seg_set_ece(seg)   ((seg)->flags & RTE_TCP_ECE_FLAG)
#define seg_set_cwr(seg)   ((seg)->flags & RTE_TCP_CWR_FLAG)

#define SEQ_LT(seq0, seq1)    ((int)((seq0) - (seq1)) < 0)
#define SEQ_LE(seq0, seq1)    ((int)((seq0) - (seq1)) <= 0)
#define SEQ_GT(seq0, seq1)    ((int)((seq0) - (seq1)) > 0)
#define SEQ_GE(seq0, seq1)    ((int)((seq0) - (seq1)) >= 0)



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

    sem_t   sem;            //used to sync
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

    fnp_ring_t* accept;
    fnp_ring_t* txbuf;
    fnp_ring_t* rxbuf;
    struct tcp_ofo_segment* ofo_head;
    struct rte_timer timers[TCPT_NTIMERS];
} tcp_sock_t;

enum tcp_state {
    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECV,
    TCP_ESTABLISHED, TCP_CLOSE_WAIT, TCP_LAST_ACK, TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2, TCP_CLOSING, TCP_TIME_WAIT, TCP_STATE_END
};

extern char* tcp_state_str[11];

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

void* fnp_tcp_sock(u32 lip, u16 lport, u32 rip, u16 rport);

void tcp_free_sock(void* sock);

void tcp_connect(tcp_sock_t* sk);

i32 tcp_send(tcp_sock_t* sk, u8* buf, i32 len);

/* only be used when socket can't find */
void tcp_send_rst(tcp_seg_t* cb);

void tcp_output(tcp_sock_t* sk);

void tcp_send_ack(tcp_sock_t* sk, bool delay);

void tcp_recv_mbuf(rte_mbuf* m);

#endif //FNP_TCP_H
