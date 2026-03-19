#ifndef FNP_ICMP_H
#define FNP_ICMP_H

#include "fnp_network.h"

int icmp_module_init(void);

void icmp_send_port_unreachable(struct rte_mbuf* orig_mbuf);

#endif //FNP_ICMP_H
