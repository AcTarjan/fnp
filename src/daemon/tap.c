#include "tap.h"

#include "fnp.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fsocket.h"
#include "fnp_worker.h"
#include "ether.h"

#include <rte_ether.h>
#include <rte_rwlock.h>
#include <string.h>

#define TAP_SOCKET_BURST_SIZE 32

typedef struct tap_socket
{
    fsocket_t socket;
    fnp_device_t* dev;
    bool is_registered;
} tap_socket_t;

typedef struct tap_context
{
    rte_rwlock_t lock;
    tap_socket_t* sockets[FNP_MAX_DEVICE_NUM];
} tap_context_t;

static tap_context_t tap_context;

static inline tap_socket_t* tap_socket_cast(fsocket_t* socket)
{
    return (tap_socket_t*)socket;
}

static inline tap_socket_t* tap_lookup_socket_locked(const fnp_device_t* dev)
{
    if (dev == NULL || dev->id >= FNP_MAX_DEVICE_NUM)
    {
        return NULL;
    }

    return tap_context.sockets[dev->id];
}

static int tap_init_context(void)
{
    memset(&tap_context, 0, sizeof(tap_context));
    rte_rwlock_init(&tap_context.lock);
    return FNP_OK;
}

static int tap_socket_register(tap_socket_t* socket)
{
    if (socket == NULL || socket->dev == NULL || socket->dev->id >= FNP_MAX_DEVICE_NUM)
    {
        return FNP_ERR_PARAM;
    }

    rte_rwlock_write_lock(&tap_context.lock);
    if (tap_context.sockets[socket->dev->id] != NULL)
    {
        rte_rwlock_write_unlock(&tap_context.lock);
        return FNP_ERR_OCCUPIED;
    }

    tap_context.sockets[socket->dev->id] = socket;
    socket->is_registered = true;
    rte_rwlock_write_unlock(&tap_context.lock);
    return FNP_OK;
}

static void tap_socket_unregister(tap_socket_t* socket)
{
    if (socket == NULL || socket->dev == NULL || socket->dev->id >= FNP_MAX_DEVICE_NUM)
    {
        return;
    }

    rte_rwlock_write_lock(&tap_context.lock);
    if (tap_context.sockets[socket->dev->id] == socket)
    {
        tap_context.sockets[socket->dev->id] = NULL;
    }
    socket->is_registered = false;
    rte_rwlock_write_unlock(&tap_context.lock);
}

static void tap_fsocket_recv(fsocket_t* socket, struct rte_mbuf* m)
{
    fmbuf_info_t* info = get_fmbuf_info(m);
    memset(info, 0, sizeof(*info));

    if (unlikely(!fsocket_enqueue_for_app(socket, m)))
    {
        free_mbuf(m);
    }
}

void tap_device_output(struct rte_mbuf* m, fnp_device_t* dev)
{
    if (unlikely(m == NULL || !is_tap_device(dev)))
    {
        free_mbuf(m);
        return;
    }

    rte_rwlock_read_lock(&tap_context.lock);
    tap_socket_t* socket = tap_lookup_socket_locked(dev);
    if (likely(socket != NULL))
    {
        get_fsocket_ops(socket->socket.type)->recv(&socket->socket, m);
    }
    else
    {
        free_mbuf(m);
    }
    rte_rwlock_read_unlock(&tap_context.lock);
}

static void tap_socket_send_one(fsocket_t* socket, struct rte_mbuf* m)
{
    (void)socket;
    if (unlikely(m == NULL || m->pkt_len < RTE_ETHER_HDR_LEN))
    {
        free_mbuf(m);
        return;
    }

    ether_recv_mbuf(m);
}

static void tap_socket_send(fsocket_t* socket, u64 tsc)
{
    struct rte_mbuf* mbufs[TAP_SOCKET_BURST_SIZE] = {0};
    u32 n = fnp_ring_dequeue_burst(socket->tx, (void**)mbufs, TAP_SOCKET_BURST_SIZE);
    for (u32 i = 0; i < n; ++i)
    {
        tap_socket_send_one(socket, mbufs[i]);
    }

    if (n > 0)
    {
        socket->polling_tsc = tsc;
    }
}

static void tap_socket_close(fsocket_t* socket)
{
    tap_socket_t* tap_socket = tap_socket_cast(socket);
    if (tap_socket->is_registered)
    {
        tap_socket_unregister(tap_socket);
    }

    fsocket_cleanup(socket);
    fnp_free(tap_socket);
}

static fsocket_t* tap_socket_create(void* conf)
{
    const fnp_tap_socket_conf_t* tap_conf = conf;
    if (unlikely(tap_conf == NULL || tap_conf->dev_name[0] == '\0'))
    {
        return NULL;
    }

    fnp_device_t* dev = lookup_device_by_name(tap_conf->dev_name);
    if (unlikely(dev == NULL || !is_tap_device(dev)))
    {
        return NULL;
    }

    tap_socket_t* tap_socket = fnp_zmalloc(sizeof(*tap_socket));
    if (unlikely(tap_socket == NULL))
    {
        return NULL;
    }

    fsocket_t* socket = &tap_socket->socket;
    fsocket_init_base(socket, fsocket_type_tap);
    tap_socket->dev = dev;
    socket->is_ready = 1;
    fsocket_format_suffix_name(socket, "TAP", dev->name);

    if (fsocket_create_io_rings(socket, true) != FNP_OK)
    {
        tap_socket_close(socket);
        return NULL;
    }

    if (tap_socket_register(tap_socket) != FNP_OK)
    {
        tap_socket_close(socket);
        return NULL;
    }

    printf("create socket %s\n", socket->name);
    return socket;
}

static const fsocket_ops_t tap_fsocket_ops = {
    .create = tap_socket_create,
    .close = tap_socket_close,
    .send = tap_socket_send,
    .recv = tap_fsocket_recv,
};

int tap_module_init(void)
{
    int ret = tap_init_context();
    CHECK_RET(ret);

    return register_fsocket_ops(fsocket_type_tap, &tap_fsocket_ops);
}
