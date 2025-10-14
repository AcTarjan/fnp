#ifndef FNP_UDP_H
#define FNP_UDP_H

#include "fsocket.h"

typedef void (*udp_send_func)(void*, struct rte_mbuf*);

typedef struct udp_sock
{
    fsocket_t socket;
} udp_sock_t;

// 创建一个udp套接字
udp_sock_t* udp_create_sock(fsockaddr_t* local, fsockaddr_t* remote);

void free_udp_sock(udp_sock_t* sock);

void udp_send_mbuf(fsocket_t* socket, struct rte_mbuf* m);

void udp_handle_fsocket_event(fsocket_t* socket, u64 event);

#endif // FNP_UDP_H
