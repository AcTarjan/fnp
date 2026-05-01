#ifndef FNP_INTERNAL_H
#define FNP_INTERNAL_H

#include "fnp.h"
#include "fnp_api.h"
#include "fnp_frontend.h"
#include "fnp_socket.h"
#include <sys/eventfd.h>

extern fnp_frontend_t *frontend;

struct fnp_socket
{
    fsocket_t *shared;
    u32 slot_index;
    u16 conf_len;
    int wait_epfd;
    fnp_handler_func handler;
    void *handler_arg;
    u8 conf[FAPI_SOCKET_CONF_MAX_LEN];
};

typedef struct fnp_frontend_local
{
    fnp_socket_t **sockets;
    u32 capacity;
} fnp_frontend_local_t;

extern fnp_frontend_local_t frontend_local;

static inline void fsocket_notify_backend(fsocket_t *socket)
{
    if (socket != NULL && socket->tx_efd_in_frontend >= 0 && socket->tx_efd_in_backend >= 0)
    {
        eventfd_write(socket->tx_efd_in_frontend, 1);
    }
}

int frontend_init_tables(u32 initial_capacity);

void frontend_cleanup_local_state(void);

fnp_socket_t *frontend_add_fsocket(fsocket_t *shared_socket, const void *conf, u16 conf_len);

void frontend_remove_fsocket(fnp_socket_t *socket);

fnp_socket_t *frontend_get_fsocket(u32 slot_index);

#endif // FNP_INTERNAL_H
