#ifndef FNP_ETHER_H
#define FNP_ETHER_H

#include <rte_ether.h>

void ether_recv_mbuf(struct rte_mbuf *m, u64 tsc);

void ether_send_mbuf(struct rte_mbuf *m, struct rte_ether_addr *dmac, u16 type);

#endif //FNP_ETHER_H
