#ifndef FNP_TCP_H
#define FNP_TCP_H

#include "fnp_common.h"
#include <rte_mbuf.h>

void tcp_init();

void tcp_output();

void tcp_recv_mbuf(struct rte_mbuf* m);

#endif //FNP_TCP_H
