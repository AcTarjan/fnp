#ifndef FNP_UDP_H
#define FNP_UDP_H

#include "fnp_socket.h"

typedef void (*udp_send_func)(void*, struct rte_mbuf*);

typedef struct udp_sock
{
    fsocket_t socket;
    udp_send_func send_func;
} udp_sock_t;

// 创建一个udp套接字
udp_sock_t* udp_create_sock(fsockaddr_t* local, fsockaddr_t* remote);

void free_udp_sock(udp_sock_t* sock);

void udp_send_mbuf(fsocket_t* socket, struct rte_mbuf* m);

void udp_fast_send_mbuf(fsocket_t* socket, struct rte_mbuf* m);

// 处理接收到的udp数据包
void udp_recv_from_net(struct rte_mbuf* m);


#endif // FNP_UDP_H
