#ifndef FSOCKET_H
#define FSOCKET_H

// 后端操作fsocket的接口

#include "fnp_socket.h"
#include <rte_ip.h>
#include <sys/eventfd.h>

static inline void fsocket_notify_backend(fsocket_t* socket)
{
 eventfd_write(socket->tx_efd_in_backend, 1);
}

static inline void fsocket_notify_frontend(fsocket_t* socket)
{
 eventfd_write(socket->rx_efd_in_backend, 1);
}

// 应用层收到一个mbuf
static inline bool fsocket_enqueue_for_app(fsocket_t* socket, void* data)
{
 if (fnp_ring_enqueue(socket->rx, data) == 0)
 {
  return false;
 }

 fsocket_notify_frontend(socket);
 return true;
}

void show_all_fsocket();

struct rte_hash* create_socket_table();

fsocket_t* lookup_socket_table(fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote);

fsocket_t* lookup_socket_table_by_ipv4(struct rte_ipv4_hdr* hdr);

/*
 协议栈worker线程调用，使用情况
 1. 用户创建socket时调用
 2. TCP创建新连接时调用
 3. picoquic创建udp socket时调用
*/
fsocket_t* create_fsocket(fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote, void* conf, int worker_id);

void close_fsocket(fsocket_t* socket);

void free_fsocket(fsocket_t* socket);

#endif //FSOCKET_H
