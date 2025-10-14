#ifndef FNP_TCP_OFO_H
#define FNP_TCP_OFO_H

#include "fnp_common.h"
#include "tcp_sock.h"

typedef struct tcp_ofo_seg
{
    picosplay_node_t node;

    /* data */
    u32 seq;
    u32 end_seq; //[seq, end_seq), 不包括end_seq
    u8 flags;
    struct rte_mbuf* data;
} tcp_ofo_seg;

void tcp_ofo_tree_init(picosplay_tree_t* tree);

tcp_ofo_seg* tcp_ofo_first_seg(tcp_sock_t* sock);

void tcp_ofo_enqueue_seg(tcp_sock_t* sock, tcp_ofo_seg* ofo_seg);

void tcp_ofo_dequeue_seg(tcp_sock_t* sock, tcp_ofo_seg* ofo_seg);

tcp_ofo_seg* tcp_ofo_init(tcp_segment* seg);

void tcp_ofo_handle_seg(tcp_sock_t* sock);

#endif //FNP_TCP_OFO_H
