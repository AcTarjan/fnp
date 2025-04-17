#ifndef FNP_UDP_H
#define FNP_UDP_H

#include "fnp_socket.h"

typedef void (*udp_send_func)(void *, struct rte_mbuf *);

typedef struct udp_sock
{
    fsocket_t socket;
    udp_send_func send_func;
} udp_sock_t;

// 创建一个udp套接字
udp_sock_t *create_udp_sock();

void free_udp_sock(udp_sock_t *sock);

void udp_send_mbuf(udp_sock_t *sock, struct rte_mbuf *m);

void udp_fast_send_mbuf(udp_sock_t *sock, struct rte_mbuf *m);

// 用于quic数据发送/接收
struct rte_mbuf *udp_recv_data(fsocket_t *socket, faddr_t *remote);
int udp_sendto(fsocket_t *socket, struct rte_mbuf *m, faddr_t *remote);

// 处理接收到的udp数据包
void udp_recv_from_net(struct rte_mbuf *m);

void udp_recv_from_app(fsocket_t *socket);

#endif // FNP_UDP_H
