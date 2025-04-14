#ifndef FNP_UDP_H
#define FNP_UDP_H

#include "fnp_socket.h"

typedef void (*udp_send_func)(void *, struct rte_mbuf *);

typedef struct udp_sock
{
    fnp_socket_t socket;
    udp_send_func send_func;
} udp_sock_t;

// 创建一个udp套接字
udp_sock_t *create_udp_sock();

void free_udp_sock(udp_sock_t *sock);

void udp_send_mbuf(udp_sock_t *sock, struct rte_mbuf *m);

void udp_fast_send_mbuf(udp_sock_t *sock, struct rte_mbuf *m);

// 处理接收到的udp数据包
void udp_recv_from_net(struct rte_mbuf *m);

void udp_recv_from_app(fnp_socket_t *socket);

#endif // FNP_UDP_H
