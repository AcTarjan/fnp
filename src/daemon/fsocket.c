#include "fsocket.h"

#include "fnp_error.h"
#include "fnp_master.h"
#include "fnp_worker.h"

#include <string.h>
#include <unistd.h>

#define FSOCKET_OPS_TABLE_SIZE 256
#define FSOCKET_IO_RING_SIZE 8192

static void fsocket_recv_unsupported(fsocket_t* socket, struct rte_mbuf* m)
{
    (void)socket;
    free_mbuf(m);
}

static const fsocket_ops_t fsocket_unsupported_ops = {
    .recv = fsocket_recv_unsupported,
};

static const fsocket_ops_t* fsocket_ops_table[FSOCKET_OPS_TABLE_SIZE];

static fsocket_t* create_fsocket_register(fsocket_type_t type, fsocket_t* socket)
{
    const fsocket_ops_t* ops = get_fsocket_ops(type);
    if (socket == NULL)
    {
        return NULL;
    }

    if (fnp_master_add_fsocket(socket) != FNP_OK)
    {
        if (ops != NULL && ops->close != NULL)
        {
            ops->close(socket);
        }
        return NULL;
    }

    return socket;
}

const fsocket_ops_t* get_fsocket_ops(fsocket_type_t type)
{
    u32 index = (u8)type;
    if (unlikely(index >= FSOCKET_OPS_TABLE_SIZE))
    {
        return &fsocket_unsupported_ops;
    }

    const fsocket_ops_t* ops = fsocket_ops_table[index];
    return ops == NULL ? &fsocket_unsupported_ops : ops;
}

int init_fsocket_layer(void)
{
    memset(fsocket_ops_table, 0, sizeof(fsocket_ops_table));
    return FNP_OK;
}

int register_fsocket_ops(fsocket_type_t type, const fsocket_ops_t* ops)
{
    u32 index = (u8)type;
    if (unlikely(index >= FSOCKET_OPS_TABLE_SIZE || ops == NULL))
    {
        return FNP_ERR_PARAM;
    }

    fsocket_ops_table[index] = ops;
    return FNP_OK;
}

void fsocket_init_base(fsocket_t* socket, fsocket_type_t type)
{
    socket->type = type;
    socket->rx_efd_in_frontend = -1;
    socket->tx_efd_in_frontend = -1;
    socket->rx_efd_in_backend = -1;
    socket->tx_efd_in_backend = -1;
    socket->polling_worker = -1;
    socket->polling_tsc = 0;
    socket->frontend_flags = 0;
}

int fsocket_create_io_rings(fsocket_t* socket, bool is_mp)
{
    socket->rx = fnp_ring_create(FSOCKET_IO_RING_SIZE, is_mp, false);
    if (socket->rx == NULL)
    {
        return FNP_ERR_CREATE_RING;
    }

    socket->rx_efd_in_backend = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (socket->rx_efd_in_backend < 0)
    {
        return FNP_ERR_CREATE_EVENTFD;
    }

    socket->tx = fnp_ring_create(FSOCKET_IO_RING_SIZE, false, false);
    if (socket->tx == NULL)
    {
        return FNP_ERR_CREATE_RING;
    }

    socket->tx_efd_in_backend = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (socket->tx_efd_in_backend < 0)
    {
        return FNP_ERR_CREATE_EVENTFD;
    }

    return FNP_OK;
}

void fsocket_format_transport_name(fsocket_t* socket, const char* prefix,
                                   const fsockaddr_t* local, const fsockaddr_t* remote)
{
    char* local_ip = fnp_ipv4_ntos(local->ip);
    char* remote_ip = fnp_ipv4_ntos(remote->ip);
    u16 local_port = fnp_swap16(local->port);
    u16 remote_port = fnp_swap16(remote->port);

    snprintf(socket->name, sizeof(socket->name), "%s-%s:%u->%s:%u",
             prefix, local_ip, local_port, remote_ip, remote_port);

    fnp_string_free(local_ip);
    fnp_string_free(remote_ip);
}

void fsocket_format_local_name(fsocket_t* socket, const char* prefix, const fsockaddr_t* local)
{
    char* local_ip = fnp_ipv4_ntos(local->ip);
    snprintf(socket->name, sizeof(socket->name), "%s-%s", prefix, local_ip);
    fnp_string_free(local_ip);
}

void fsocket_format_suffix_name(fsocket_t* socket, const char* prefix, const char* suffix)
{
    snprintf(socket->name, sizeof(socket->name), "%s-%s", prefix, suffix);
}

void fsocket_cleanup(fsocket_t* socket)
{
    struct rte_mbuf* m = NULL;
    if (socket->rx != NULL)
    {
        while (fnp_ring_dequeue(socket->rx, (void**)&m))
        {
            free_mbuf(m);
        }
        fnp_ring_free(socket->rx);
    }

    if (socket->tx != NULL)
    {
        while (fnp_ring_dequeue(socket->tx, (void**)&m))
        {
            free_mbuf(m);
        }
        fnp_ring_free(socket->tx);
    }

    if (socket->rx_efd_in_backend >= 0)
    {
        close(socket->rx_efd_in_backend);
    }
    if (socket->tx_efd_in_backend >= 0)
    {
        close(socket->tx_efd_in_backend);
    }
}

fsocket_t* create_fsocket(fsocket_type_t type, void* conf)
{
    const fsocket_ops_t* ops = get_fsocket_ops(type);
    if (ops == NULL || ops->create == NULL)
    {
        printf("socket type %d is not enabled in this build\n", type);
        return NULL;
    }

    return create_fsocket_register(type, ops->create(conf));
}

void close_fsocket(fsocket_t* socket)
{
    if (socket == NULL)
    {
        return;
    }

    const fsocket_ops_t* ops = get_fsocket_ops(socket->type);
    if (ops != NULL && ops->close != NULL)
    {
        ops->close(socket);
    }
}

void free_fsocket(fsocket_t* socket)
{
    close_fsocket(socket);
}

void show_all_fsocket(void)
{
    FNP_INFO("socket tables are owned by active protocol modules\n");
}
