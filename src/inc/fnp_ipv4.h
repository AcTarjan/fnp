#ifndef FNP_IPV4_H
#define FNP_IPV4_H

#include "fnp_common.h"

typedef void (*ipv4_recv_handler)(rte_mbuf*);

#define IPV4_HDR_LEN        20

void ipv4_recv_mbuf(rte_mbuf *m, u64 tsc);

void ipv4_send_mbuf(rte_mbuf *m, u32 rip, u8 proto);

void ipv4_register(int proto, ipv4_recv_handler h);

#endif //FNP_IPV4_H
