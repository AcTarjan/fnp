#ifndef FNP_ETHER_H
#define FNP_ETHER_H

#include "fnp_network.h"

#include <rte_ether.h>

typedef void (*ether_input_func)(struct rte_mbuf* m);

int init_ether_layer(void);

int ether_register_input(u16 ethertype, ether_input_func input);

void ether_recv_mbuf(struct rte_mbuf* m);

void ether_send_mbuf(struct rte_mbuf* m, struct rte_ether_addr* dmac, u16 type);

#endif //FNP_ETHER_H
