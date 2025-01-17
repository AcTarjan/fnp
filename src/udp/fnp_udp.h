#ifndef FNP_UDP_H
#define FNP_UDP_H

#include "ipv4_5tuple.h"
#include "fnp_sock.h"

typedef struct udp_sock {
    sock_t sock;        // must be the first field
} udp_sock_t;

//根据ipv4_5tuple创建一个udp_sock
udp_sock_t* udp_sock_ipv4(ipv4_5tuple_t* key);

void udp_recv_mbuf(struct rte_mbuf* m);

void udp_send_mbuf(struct rte_mbuf* m);

#endif //FNP_UDP_H
