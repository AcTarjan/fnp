#ifndef FSOCKET_H
#define FSOCKET_H

#include "fnp_socket.h"


struct rte_hash* create_socket_table();

fsocket_t* lookup_socket_table(fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote);

fsocket_t* lookup_socket_table_by_ipv4(struct rte_ipv4_hdr* hdr);

int fnp_socket_init(fsocket_t* socket, fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote);

/*
 协议栈worker线程调用，使用情况
 1. 用户创建socket时调用
 2. TCP创建新连接时调用
 3. picoquic创建udp socket时调用
*/
fsocket_t* create_fsocket(fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote, void* conf, int worker_id);

void free_fsocket(fsocket_t* socket);

#endif //FSOCKET_H
