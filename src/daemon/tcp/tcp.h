#ifndef FNP_TCP_H
#define FNP_TCP_H

/*
 * TCP层对外的接口文件
 */

#include "tcp_sock.h"

void init_tcp_layer();

// 接收来自应用层的tcp数据，并发送给TCP协议
void tcp_recv_from_app(fsocket_t *socket);

// 接收来自网络的TCP数据，并发送给TCP协议
void tcp_recv_mbuf(struct rte_mbuf *m);

// 将TCP协议
void tcp_output_to_net();

#endif // FNP_TCP_H
