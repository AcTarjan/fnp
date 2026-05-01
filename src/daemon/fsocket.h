#ifndef FSOCKET_H
#define FSOCKET_H

// 后端操作fsocket的接口

#include "fnp_socket.h"
#include <stddef.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <sys/eventfd.h>

static inline void fsocket_notify_backend(fsocket_t *socket)
{
    if (socket != NULL && socket->tx_efd_in_backend >= 0)
    {
        eventfd_write(socket->tx_efd_in_backend, 1);
    }
}

static inline fsocket_t *fsocket_cast(void *socket)
{
    return (fsocket_t *)socket;
}

void show_all_fsocket();

int init_fsocket_layer(void);

void fsocket_init_base(fsocket_t *socket, fsocket_type_t type);

int fsocket_create_io_rings(fsocket_t *socket, bool is_mp);

// 将数据入队到socket的rx队列, 供应用层读取, 如果队列满了则丢包
void fsocket_enqueue_for_app(fsocket_t *socket, struct rte_mbuf *m);

void fsocket_cleanup(fsocket_t *socket);

void fsocket_format_transport_name(fsocket_t *socket, const char *prefix,
                                   const fsockaddr_t *local, const fsockaddr_t *remote);

void fsocket_format_local_name(fsocket_t *socket, const char *prefix, const fsockaddr_t *local);

void fsocket_format_suffix_name(fsocket_t *socket, const char *prefix, const char *suffix);

fsocket_t *create_fsocket(fsocket_type_t type, void *conf, void *ctx);

int export_fsocket_conf(const fsocket_t *socket, void *conf, u16 *conf_len);

void close_fsocket(fsocket_t *socket);

void free_fsocket(fsocket_t *socket);

#endif // FSOCKET_H
