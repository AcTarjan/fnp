#ifndef FNP_ETHER_H
#define FNP_ETHER_H

#include "fnp_iface.h"

#include <rte_ether.h>

void ether_recv_mbuf(fnp_iface_t* iface, struct rte_mbuf *m);

void ether_send_mbuf(fnp_iface_t* iface, struct rte_mbuf *m, struct rte_ether_addr *dmac, u16 type);

#endif //FNP_ETHER_H
