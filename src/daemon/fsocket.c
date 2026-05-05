#include "fsocket.h"

#include "fnp_error.h"
#include "fnp_context.h"
#include "gtpu.h"
#include "fnp_master.h"
#include "fnp_worker.h"
#include "transport.h"

#include <string.h>
#include <unistd.h>

#define FSOCKET_IO_RING_SIZE 8192

static int fsocket_ring_size_or_default(int configured)
{
    if (configured >= 2 && (configured & (configured - 1)) == 0)
    {
        return configured;
    }
    return FSOCKET_IO_RING_SIZE;
}

int init_fsocket_layer(void)
{
    return FNP_OK;
}

static const char *fsocket_type_name(fsocket_type_t type)
{
    switch (type)
    {
    case fsocket_type_gtpu:
        return "GTPU";
    default:
        return "UNKNOWN";
    }
}

static int register_fsocket_to_master(fsocket_t *socket)
{
    if (socket->tx_efd_in_backend < 0)
    {
        return FNP_OK;
    }

    if (fnp_master_add_fsocket(socket) != FNP_OK)
    {
        FNP_ERR("register_fsocket: fail to add fsocket %s into master table\n",
                socket->name);

        transport_context_t *transport = transport_from_socket(socket);
        if (transport->ops != NULL && transport->ops->close != NULL)
        {
            transport->ops->close(transport);
        }
        return FNP_ERR_PARAM;
    }

    fsocket_master_set_registered(socket, true);
    FNP_DEBUG("register_fsocket_to_master: added fsocket name=%s type=%s(%d)\n",
              socket->name, fsocket_type_name(socket->type), socket->type);
    return FNP_OK;
}

void fsocket_init_base(fsocket_t *socket, fsocket_type_t type)
{
    socket->type = type;
    socket->tx_efd_in_frontend = -1;
    socket->tx_efd_in_backend = -1;
    socket->frontend_id = 0;
    socket->egress_worker = -1;
    socket->ingress_worker = -1;
    socket->polling_tsc = 0;
    socket->frontend_attached = 0;
    socket->master_registered = 0;
    socket->polling_cmd_pending = 0;
    socket->close_requested = 0;
    socket->is_closed = 0;
    socket->lifecycle_state = fsocket_lifecycle_active;
    fsocket_ref_init(socket);
}

void fsocket_enqueue_for_app(fsocket_t *socket, struct rte_mbuf *m)
{
    if (unlikely(socket == NULL || socket->rx == NULL || m == NULL))
    {
        free_mbuf(m);
        return;
    }

    if (unlikely(fnp_ring_enqueue(socket->rx, m) == 0))
    {
        __atomic_add_fetch(&socket->rx_ring_drops, 1, __ATOMIC_RELAXED);
        free_mbuf(m);
    }
}

int fsocket_create_io_rings(fsocket_t *socket)
{
    fnp_config *conf = &get_fnp_context()->conf;
    int rx_ring_size = fsocket_ring_size_or_default(conf->socket_rx_ring_size);
    int tx_ring_size = fsocket_ring_size_or_default(conf->socket_tx_ring_size);

    socket->rx = fnp_ring_create(rx_ring_size, false, false);
    if (socket->rx == NULL)
    {
        return FNP_ERR_CREATE_RING;
    }

    socket->tx = fnp_ring_create(tx_ring_size, false, false);
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

void fsocket_format_transport_name(fsocket_t *socket, const char *prefix,
                                   const fsockaddr_t *local, const fsockaddr_t *remote)
{
    char *local_ip = fnp_ipv4_ntos(local->ip);
    char *remote_ip = fnp_ipv4_ntos(remote->ip);
    u16 local_port = fnp_swap16(local->port);
    u16 remote_port = fnp_swap16(remote->port);

    snprintf(socket->name, sizeof(socket->name), "%s-%s:%u->%s:%u",
             prefix, local_ip, local_port, remote_ip, remote_port);

    fnp_string_free(local_ip);
    fnp_string_free(remote_ip);
}

void fsocket_format_local_name(fsocket_t *socket, const char *prefix, const fsockaddr_t *local)
{
    char *local_ip = fnp_ipv4_ntos(local->ip);
    snprintf(socket->name, sizeof(socket->name), "%s-%s", prefix, local_ip);
    fnp_string_free(local_ip);
}

void fsocket_format_suffix_name(fsocket_t *socket, const char *prefix, const char *suffix)
{
    snprintf(socket->name, sizeof(socket->name), "%s-%s", prefix, suffix);
}

void fsocket_cleanup(fsocket_t *socket)
{
    struct rte_mbuf *m = NULL;
    if (socket->rx != NULL)
    {
        while (fnp_ring_dequeue(socket->rx, (void **)&m))
        {
            free_mbuf(m);
        }
        fnp_ring_free(socket->rx);
    }

    if (socket->tx != NULL)
    {
        while (fnp_ring_dequeue(socket->tx, (void **)&m))
        {
            free_mbuf(m);
        }
        fnp_ring_free(socket->tx);
    }

    if (socket->tx_efd_in_backend >= 0)
    {
        close(socket->tx_efd_in_backend);
    }
}

fsocket_t *create_fsocket(fsocket_type_t type, void *conf, void *ctx)
{
    FNP_DEBUG("create_fsocket: type=%s(%d) begin\n", fsocket_type_name(type), type);

    fsocket_t *socket = NULL;
    switch (type)
    {
    case fsocket_type_gtpu:
        socket = gtpu_create_transport(conf, ctx);
        break;
    default:
        printf("socket type %d is not enabled in this build\n", type);
        return NULL;
    }

    if (socket == NULL)
    {
        printf("failed to create socket of type %d\n", type);
        return NULL;
    }

    int ret = register_fsocket_to_master(socket);
    if (ret != FNP_OK)
    {
        return NULL;
    }

    return socket;
}

void close_fsocket(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return;
    }

    if (!fsocket_request_close(socket))
    {
        return;
    }

    if (fnp_worker_close_fsocket(socket) == FNP_OK)
    {
        return;
    }

    transport_context_t *transport = transport_from_socket(socket);
    if (fsocket_enter_closing(socket) && transport->ops != NULL && transport->ops->close != NULL)
    {
        transport->ops->close(transport);
    }
}

void free_fsocket(fsocket_t *socket)
{
    close_fsocket(socket);
}

void show_all_fsocket(void)
{
    FNP_INFO("socket tables are owned by active protocol modules\n");
}
