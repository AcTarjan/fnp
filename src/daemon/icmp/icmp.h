#ifndef FNP_ICMP_H
#define FNP_ICMP_H

#include "fnp_iface.h"

void icmp_send_port_unreachable(struct rte_mbuf* orig_mbuf);

void icmp_recv_mbuf(struct rte_mbuf* m);

#endif //FNP_ICMP_H
