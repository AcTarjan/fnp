#include "tun.h"

#include "fnp.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fsocket.h"
#include "fnp_worker.h"
#include "ipv4.h"

#include <rte_ip.h>
#include <rte_rwlock.h>
#include <string.h>

#define TUN_SOCKET_BURST_SIZE 32

typedef struct tun_socket
{
    fsocket_t socket;
    fnp_device_t* dev;
    bool is_registered;
} tun_socket_t;

typedef struct tun_context
{
    rte_rwlock_t lock;
    tun_socket_t* sockets[FNP_MAX_DEVICE_NUM];
} tun_context_t;

static tun_context_t tun_context;

static inline tun_socket_t* tun_socket_cast(fsocket_t* socket)
{
    return (tun_socket_t*)socket;
}

static inline tun_socket_t* tun_lookup_socket_locked(const fnp_device_t* dev)
{
    if (dev == NULL || dev->id >= FNP_MAX_DEVICE_NUM)
    {
        return NULL;
    }

    return tun_context.sockets[dev->id];
}

static int tun_init_context(void)
{
    memset(&tun_context, 0, sizeof(tun_context));
    rte_rwlock_init(&tun_context.lock);
    return FNP_OK;
}

static int tun_socket_register(tun_socket_t* socket)
{
    if (socket == NULL || socket->dev == NULL || socket->dev->id >= FNP_MAX_DEVICE_NUM)
    {
        return FNP_ERR_PARAM;
    }

    rte_rwlock_write_lock(&tun_context.lock);
    if (tun_context.sockets[socket->dev->id] != NULL)
    {
        rte_rwlock_write_unlock(&tun_context.lock);
        return FNP_ERR_OCCUPIED;
    }

    tun_context.sockets[socket->dev->id] = socket;
    socket->is_registered = true;
    rte_rwlock_write_unlock(&tun_context.lock);
    return FNP_OK;
}

static void tun_socket_unregister(tun_socket_t* socket)
{
    if (socket == NULL || socket->dev == NULL || socket->dev->id >= FNP_MAX_DEVICE_NUM)
    {
        return;
    }

    rte_rwlock_write_lock(&tun_context.lock);
    if (tun_context.sockets[socket->dev->id] == socket)
    {
        tun_context.sockets[socket->dev->id] = NULL;
    }
    socket->is_registered = false;
    rte_rwlock_write_unlock(&tun_context.lock);
}

static void tun_fsocket_recv(fsocket_t* socket, struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    char *src_ip = fnp_ipv4_ntos(hdr->src_addr);
    char *dst_ip = fnp_ipv4_ntos(hdr->dst_addr);
    FNP_DEBUG("tun_fsocket_recv: socket=%s proto=%u src=%s dst=%s pkt_len=%u\n",
              socket->name,
              hdr->next_proto_id,
              src_ip == NULL ? "0.0.0.0" : src_ip,
              dst_ip == NULL ? "0.0.0.0" : dst_ip,
              m->pkt_len);
    fnp_string_free(src_ip);
    fnp_string_free(dst_ip);
    fmbuf_info_t* info = get_fmbuf_info(m);
    info->remote.family = FSOCKADDR_IPV4;
    info->remote.ip = hdr->src_addr;
    info->remote.port = 0;
    info->local.family = FSOCKADDR_IPV4;
    info->local.ip = hdr->dst_addr;
    info->local.port = 0;

    if (unlikely(!fsocket_enqueue_for_app(socket, m)))
    {
        free_mbuf(m);
    }
}

void tun_device_send(fnp_device_t* dev,
                     struct rte_mbuf* m,
                     const struct rte_ether_addr* dmac)
{
    (void)dmac;

    if (unlikely(m == NULL || !is_tun_device(dev)))
    {
        free_mbuf(m);
        return;
    }

    rte_rwlock_read_lock(&tun_context.lock);
    tun_socket_t* socket = tun_lookup_socket_locked(dev);
    if (likely(socket != NULL))
    {
        struct rte_ipv4_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
        char *src_ip = fnp_ipv4_ntos(hdr->src_addr);
        char *dst_ip = fnp_ipv4_ntos(hdr->dst_addr);
        FNP_DEBUG("tun_device_send: dev=%s socket=%s proto=%u src=%s dst=%s pkt_len=%u\n",
                  dev->name,
                  socket->socket.name,
                  hdr->next_proto_id,
                  src_ip == NULL ? "0.0.0.0" : src_ip,
                  dst_ip == NULL ? "0.0.0.0" : dst_ip,
                  m->pkt_len);
        fnp_string_free(src_ip);
        fnp_string_free(dst_ip);
        get_fsocket_ops(socket->socket.type)->recv(&socket->socket, m);
    }
    else
    {
        free_mbuf(m);
    }
    rte_rwlock_read_unlock(&tun_context.lock);
}

static void tun_socket_send_one(fsocket_t* socket, struct rte_mbuf* m)
{
    struct rte_ipv4_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
    char *src_ip = fnp_ipv4_ntos(hdr->src_addr);
    char *dst_ip = fnp_ipv4_ntos(hdr->dst_addr);
    FNP_DEBUG("tun_socket_send_one: socket=%s inject proto=%u src=%s dst=%s pkt_len=%u\n",
              socket->name,
              hdr->next_proto_id,
              src_ip == NULL ? "0.0.0.0" : src_ip,
              dst_ip == NULL ? "0.0.0.0" : dst_ip,
              m->pkt_len);
    fnp_string_free(src_ip);
    fnp_string_free(dst_ip);
    ipv4_tun_input(m);
}

static void tun_socket_send(fsocket_t* socket, u64 tsc)
{
    struct rte_mbuf* mbufs[TUN_SOCKET_BURST_SIZE] = {0};
    u32 n = fnp_ring_dequeue_burst(socket->tx, (void**)mbufs, TUN_SOCKET_BURST_SIZE);
    if (n > 0)
    {
        FNP_DEBUG("tun_socket_send: socket=%s burst=%u\n", socket->name, n);
    }
    for (u32 i = 0; i < n; ++i)
    {
        tun_socket_send_one(socket, mbufs[i]);
    }

    if (n > 0)
    {
        socket->polling_tsc = tsc;
    }
}

static void tun_socket_close(fsocket_t* socket)
{
    tun_socket_t* tun_socket = tun_socket_cast(socket);
    if (tun_socket->is_registered)
    {
        tun_socket_unregister(tun_socket);
    }

    fsocket_cleanup(socket);
    fnp_free(tun_socket);
}

static fsocket_t* tun_socket_create(void* conf)
{
    const fnp_tun_socket_conf_t* tun_conf = conf;
    if (unlikely(tun_conf == NULL || tun_conf->dev_name[0] == '\0'))
    {
        return NULL;
    }

    fnp_device_t* dev = lookup_device_by_name(tun_conf->dev_name);
    if (unlikely(dev == NULL || !is_tun_device(dev)))
    {
        return NULL;
    }

    tun_socket_t* tun_socket = fnp_zmalloc(sizeof(*tun_socket));
    if (unlikely(tun_socket == NULL))
    {
        return NULL;
    }

    fsocket_t* socket = &tun_socket->socket;
    fsocket_init_base(socket, fsocket_type_tun);
    tun_socket->dev = dev;
    socket->is_ready = 1;
    fsocket_format_suffix_name(socket, "TUN", dev->name);

    if (fsocket_create_io_rings(socket, true) != FNP_OK)
    {
        tun_socket_close(socket);
        return NULL;
    }

    if (tun_socket_register(tun_socket) != FNP_OK)
    {
        tun_socket_close(socket);
        return NULL;
    }

    printf("create socket %s\n", socket->name);
    return socket;
}

static const fsocket_ops_t tun_fsocket_ops = {
    .create = tun_socket_create,
    .close = tun_socket_close,
    .send = tun_socket_send,
    .recv = tun_fsocket_recv,
};

int tun_module_init(void)
{
    int ret = tun_init_context();
    CHECK_RET(ret);

    return register_fsocket_ops(fsocket_type_tun, &tun_fsocket_ops);
}
