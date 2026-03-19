#ifndef FSOCKET_H
#define FSOCKET_H

// 后端操作fsocket的接口

#include "fnp_socket.h"
#include <stddef.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
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

    if (fsocket_frontend_eventfd_enabled(socket) &&
        !fsocket_frontend_polling_enabled(socket) &&
        fnp_ring_count(socket->rx) == 1)
    {
        fsocket_notify_frontend(socket);
    }
    return true;
}

void show_all_fsocket();

int init_fsocket_layer(void);

void fsocket_init_base(fsocket_t* socket, fsocket_type_t type);

int fsocket_create_io_rings(fsocket_t* socket, bool is_mp);

void fsocket_cleanup(fsocket_t* socket);

void fsocket_format_transport_name(fsocket_t* socket, const char* prefix,
                                   const fsockaddr_t* local, const fsockaddr_t* remote);

void fsocket_format_local_name(fsocket_t* socket, const char* prefix, const fsockaddr_t* local);

void fsocket_format_suffix_name(fsocket_t* socket, const char* prefix, const char* suffix);

typedef fsocket_t* (*fsocket_create_func)(void* conf);
typedef void (*fsocket_close_func)(fsocket_t* socket);
typedef void (*fsocket_send_func)(fsocket_t* socket, u64 tsc);
typedef void (*fsocket_recv_func)(fsocket_t* socket, struct rte_mbuf* m);

typedef struct fsocket_ops
{
    fsocket_create_func create;
    fsocket_close_func close;
    fsocket_send_func send;
    fsocket_recv_func recv;
} fsocket_ops_t;

int register_fsocket_ops(fsocket_type_t type, const fsocket_ops_t* ops);

const fsocket_ops_t* get_fsocket_ops(fsocket_type_t type);

fsocket_t* create_fsocket(fsocket_type_t type, void* conf);

void close_fsocket(fsocket_t* socket);

void free_fsocket(fsocket_t* socket);

#endif //FSOCKET_H
