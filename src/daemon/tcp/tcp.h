#ifndef FNP_TCP_H
#define FNP_TCP_H

/*
 * TCP层对外的接口文件
 */

#include "tcp_sock.h"

void init_tcp_layer();

void tcp_connect(fsocket_t* socket);

void tcp_close(fsocket_t* socket);

// 接收来自网络的TCP数据，并发送给TCP协议
void tcp_recv_mbuf(struct rte_mbuf* m);

void tcp_handle_fsocket_event(fsocket_t* socket, u64 event);

#endif // FNP_TCP_H
