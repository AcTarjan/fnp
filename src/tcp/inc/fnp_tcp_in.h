#ifndef FNP_FNP_TCP_IN_H
#define FNP_FNP_TCP_IN_H

#include <rte_tcp.h>

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



void tcp_recv_mbuf(rte_mbuf* m);

#endif //FNP_FNP_TCP_IN_H
