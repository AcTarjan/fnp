#ifndef FNP_TCP_OFO_H
#define FNP_TCP_OFO_H

#include "fnp_common.h"

struct tcp_ofo_segment;

void tcp_ofo_insert(struct tcp_ofo_segment* head, u32* seq, i32* len);

i32 tcp_ofo_top(struct tcp_ofo_segment* head, u32* rcv_nxt);

struct tcp_ofo_segment* tcp_malloc_ofo_seg();

void tcp_free_ofo_seg(struct tcp_ofo_segment* seg);

#endif //FNP_TCP_OFO_H
