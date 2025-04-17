#ifndef FNP_TCP_COMM_H
#define FNP_TCP_COMM_H

#define TCP_HDR_MIN_LEN 20
#define TCP_MAX_SEG_SIZE 1460
#define TCP_MAX_SEND_BURST 128

// 用户请求
#define TCP_USER_CONNECT 0x01
#define TCP_USER_CLOSE 0x02

#define TCP_LISTEN_BACKLOG 128

// TCP定时器
#define TCPT_NTIMERS 5
#define TCPT_REXMT 0     /* retransmit */
#define TCPT_PERSIST 1   /* retransmit persistance */
#define TCPT_DELAY_ACK 2 /* delay ack */
#define TCPT_KEEP 3      /* keep alive */
#define TCPT_2MSL 4      /* 2*msl quiet time timer */

#define TCP_MIN_CWND 2
#define TCP_MAX_CWND 1024
#define TCP_THRESHOLD 32

#define seg_set_rst(seg) ((seg)->flags & RTE_TCP_RST_FLAG)
#define seg_set_ack(seg) ((seg)->flags & RTE_TCP_ACK_FLAG)
#define seg_set_syn(seg) ((seg)->flags & RTE_TCP_SYN_FLAG)
#define seg_set_fin(seg) ((seg)->flags & RTE_TCP_FIN_FLAG)
#define seg_set_urg(seg) ((seg)->flags & RTE_TCP_URG_FLAG)
#define seg_set_psh(seg) ((seg)->flags & RTE_TCP_PSH_FLAG)
#define seg_set_ece(seg) ((seg)->flags & RTE_TCP_ECE_FLAG)
#define seg_set_cwr(seg) ((seg)->flags & RTE_TCP_CWR_FLAG)
#define seg_has_opt(seg) ((seg)->hdr_len > TCP_HDR_MIN_LEN)

#define SEQ_LT(seq0, seq1) ((int)((seq0) - (seq1)) < 0)
#define SEQ_LE(seq0, seq1) ((int)((seq0) - (seq1)) <= 0)
#define SEQ_GT(seq0, seq1) ((int)((seq0) - (seq1)) > 0)
#define SEQ_GE(seq0, seq1) ((int)((seq0) - (seq1)) >= 0)

typedef enum tcp_state
{
    TCP_NEW, //刚创建
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSING,
    TCP_TIME_WAIT,
    TCP_CLOSED,
    TCP_STATE_END
} tcp_state_t;

#define TCP_RXBUF_SIZE 10240
#define TCP_TXBUF_SIZE 10240
#define TCP_MSS 1460
#define TCP_WS_SHIFT 7

typedef struct tcp_option
{
    u8 wnd_scale;
    bool permit_sack;
    u16 mss;
} tcp_option;

typedef struct tcp_segment
{
    union
    {
        struct
        {
            u8 pad0;
            u8 proto;
            u16 pad1;
            u32 rip;
            u32 lip;
            u16 rport;
            u16 lport;
        };

        fsockaddr_t local;
        fsockaddr_t remote;
    };

    u32 seq;
    u32 ack;
    u32 rx_win;
    u16 data_len;
    u8 hdr_len;
    u8 flags;
    u16 iface_id;
    tcp_option opt;
    struct rte_mbuf* data;
} tcp_segment;

#endif // FNP_TCP_COMM_H
