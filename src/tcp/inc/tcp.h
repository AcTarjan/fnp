#ifndef FNP_TCP_H
#define FNP_TCP_H

#include "fnp_common.h"

i32 tcp_init();

void tcp_output();

void tcp_recv_mbuf(rte_mbuf* m);

#endif //FNP_TCP_H
