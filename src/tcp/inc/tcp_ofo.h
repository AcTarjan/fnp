#ifndef FNP_TCP_OFO_H
#define FNP_TCP_OFO_H

#include "fnp_common.h"
#include "rbtree.h"

typedef struct tcp_ofo_seg {
    rb_node node;

    /* data */
    u32     seq;
    u32     end_seq;       //[seq, end_seq), 不包括end_seq
    u8      flags;
} tcp_ofo_seg;

tcp_ofo_seg* tcp_ofo_malloc(u32 seq, u16 len, u8 flags);

u32 tcp_ofo_enqueue(rb_tree* rbt, tcp_ofo_seg* seg);

u8 tcp_ofo_dequeue(rb_tree* rbt, u32* rcv_nxt);

#endif //FNP_TCP_OFO_H
