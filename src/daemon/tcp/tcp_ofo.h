#ifndef FNP_TCP_OFO_H
#define FNP_TCP_OFO_H

#include "fnp_common.h"
#include "rbtree.h"
#include "tcp_sock.h"

typedef struct tcp_ofo_seg {
    rb_node node;

    /* data */
    u32     seq;
    u32     end_seq;       //[seq, end_seq), 不包括end_seq
    u8      flags;
    struct rte_mbuf *data;
} tcp_ofo_seg;

tcp_ofo_seg* tcp_ofo_malloc(tcp_segment* seg);

void tcp_ofo_free(tcp_ofo_seg* seg);

void tcp_ofo_enqueue(rb_tree* rbt, tcp_ofo_seg* seg);

u8 tcp_ofo_dequeue(tcp_sock_t* sock);

#endif //FNP_TCP_OFO_H
