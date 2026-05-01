#ifndef FNP_TRANSPORT_H
#define FNP_TRANSPORT_H

#include "fnp_socket.h"
#include "ipv4.h"

#include <rte_mbuf.h>

typedef struct transport_context transport_context_t;

typedef void (*transport_close_func)(transport_context_t *transport);
typedef void (*transport_send_func)(transport_context_t *transport, u64 tsc);
typedef void (*transport_recv_func)(transport_context_t *transport, struct rte_mbuf *m);

typedef struct transport_ops
{
    transport_close_func close;
    transport_send_func send;
    transport_recv_func recv;
} transport_ops_t;

struct transport_context
{
    fsocket_t socket;
    const transport_ops_t *ops;
    fsockaddr_t local;
    fsockaddr_t remote;
    fsockaddr_t send;
    ipv4_tx_cache_t ip_tx_cache;
};

static inline fsocket_t *transport_socket(transport_context_t *transport)
{
    return transport == NULL ? NULL : &transport->socket;
}

static inline const fsocket_t *transport_const_socket(const transport_context_t *transport)
{
    return transport == NULL ? NULL : &transport->socket;
}

static inline transport_context_t *transport_from_socket(fsocket_t *socket)
{
    return (transport_context_t *)socket;
}

static inline const transport_context_t *transport_const_from_socket(const fsocket_t *socket)
{
    return (const transport_context_t *)socket;
}

#endif // FNP_TRANSPORT_H
