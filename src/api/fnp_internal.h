#ifndef FNP_INTERNAL_H
#define FNP_INTERNAL_H

#include "fnp_frontend.h"
#include "fnp_socket.h"
#include <sys/eventfd.h>

extern fnp_frontend_t* frontend;

static inline void fsocket_notify_backend(fsocket_t* socket)
{
    eventfd_write(socket->tx_efd_in_frontend, 1);
}

static inline void frontend_add_fsocket(fsocket_t* socket)
{
    socket->frontend_id = frontend->pid;
    int fd = socket->fd;

    rte_spinlock_lock(&frontend->lock);
    frontend->socket_num++;
    frontend->fd_table[fd] = socket;
    rte_spinlock_unlock(&frontend->lock);
}

static inline void frontend_remove_fsocket(fsocket_t* socket)
{
    socket->frontend_id = 0;
    int fd = socket->fd;

    rte_spinlock_lock(&frontend->lock);
    frontend->socket_num--;
    frontend->fd_table[fd] = NULL;
    rte_spinlock_unlock(&frontend->lock);
}

static inline fsocket_t* frontend_get_fsocket(int fd)
{
    if (fd < 0 || fd >= FNP_FRONTEND_MAX_FDS)
        return NULL;

    return frontend->fd_table[fd];
}


#endif //FNP_INTERNAL_H
