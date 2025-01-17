#ifndef FNP_IPV4_H
#define FNP_IPV4_H

#include "fnp_common.h"
#include <rte_hash.h>
#include <rte_mbuf.h>

#define IPV4_HDR_LEN        20

void ipv4_init();

void ipv4_recv_mbuf(struct rte_mbuf *m, u64 tsc);

void ipv4_send_mbuf(struct rte_mbuf *m, u8 proto, u32 dst_ip);

uint32_t ipv4_ston();

#endif //FNP_IPV4_H
