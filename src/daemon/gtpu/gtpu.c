#include "gtpu.h"

#include "fnp.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_frontend.h"
#include "fnp_master.h"
#include "fnp_network.h"
#include "fnp_socket.h"
#include "fsocket.h"
#include "ipv4.h"
#include "route.h"
#include "fnp_worker.h"

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_pause.h>
#include <rte_udp.h>

#include <string.h>

#define GTPU_SOCKET_TABLE_SIZE 4096
#define GTPU_HDR_LEN 8
#define GTPU_FLAGS_V1_GPDU 0x30u
#define GTPU_MSGTYPE_GPDU 255u
#define GTPU_BURST_SIZE 32
#define GTPU_AUTO_PORT_FIRST 32768u
#define GTPU_AUTO_PORT_LAST 60999u
#define GTPU_AUTO_PORT_COUNT (GTPU_AUTO_PORT_LAST - GTPU_AUTO_PORT_FIRST + 1u)
#define GTPU_AUTO_PORT_BITMAP_WORDS ((GTPU_AUTO_PORT_COUNT + 63u) / 64u)
#define GTPU_PORT_POOL_TABLE_SIZE 128

typedef struct __attribute__((packed)) gtpu_hdr
{
    u8 flags;
    u8 msg_type;
    u16 msg_length;
    u32 teid;
} gtpu_hdr_t;

typedef struct gtpu_socket
{
    fsocket_t socket;
    fsockaddr_t local;
    fsockaddr_t remote;
    ipv4_tx_cache_t tx_cache;
    u32 incoming_teid;
    u32 outgoing_teid;
    bool is_registered;
    struct gtpu_socket *ldp_peer;
} gtpu_socket_t;

typedef struct gtpu_context
{
    struct rte_hash *global_tbl;
    rte_spinlock_t lock;
    struct rte_hash *port_pool_tbl;
    rte_spinlock_t port_pool_lock;
} gtpu_context_t;

typedef struct gtpu_port_pool
{
    u32 local_ip;
    u16 next_port_offset;
    u16 reserved0;
    rte_spinlock_t lock;
    u64 used_bitmap[GTPU_AUTO_PORT_BITMAP_WORDS];
} gtpu_port_pool_t;

static gtpu_context_t gtpu_context;
static char gtpu_local_hash_names[FNP_MAX_WORKER_NUM][32];

typedef struct gtpu_socket_key
{
    u32 teid;
    u32 local_ip;
    u16 local_port;
    u16 reserved0;
} gtpu_socket_key_t;

static inline gtpu_socket_t *gtpu_socket_cast(fsocket_t *socket)
{
    return (gtpu_socket_t *)socket;
}

static struct rte_hash *gtpu_create_hash_table(const char *name)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = GTPU_SOCKET_TABLE_SIZE,
        .key_len = sizeof(gtpu_socket_key_t),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    return rte_hash_create(&params);
}

static struct rte_hash *gtpu_create_port_pool_table(void)
{
    struct rte_hash_parameters params = {
        .name = "fnp_gtpu_port_pool_tbl",
        .entries = GTPU_PORT_POOL_TABLE_SIZE,
        .key_len = sizeof(u32),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    return rte_hash_create(&params);
}

static int gtpu_init_context(void)
{
    memset(&gtpu_context, 0, sizeof(gtpu_context));
    rte_spinlock_init(&gtpu_context.lock);
    rte_spinlock_init(&gtpu_context.port_pool_lock);
    gtpu_context.global_tbl = gtpu_create_hash_table("fnp_gtpu_global_tbl");
    if (gtpu_context.global_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    gtpu_context.port_pool_tbl = gtpu_create_port_pool_table();
    if (gtpu_context.port_pool_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    for (int worker_id = 0; worker_id < get_fnp_worker_count(); ++worker_id)
    {
        fnp_worker_t *worker = get_fnp_worker(worker_id);
        if (worker == NULL)
        {
            return FNP_ERR_PARAM;
        }

        snprintf(gtpu_local_hash_names[worker_id], sizeof(gtpu_local_hash_names[worker_id]),
                 "fnp_gtpu_rx_%d", worker_id);
        worker->gtpu_rx_tbl = gtpu_create_hash_table(gtpu_local_hash_names[worker_id]);
        if (worker->gtpu_rx_tbl == NULL)
        {
            return FNP_ERR_CREATE_HASH_TABLE;
        }
    }

    return FNP_OK;
}

static inline void gtpu_fill_key(gtpu_socket_key_t *key, u32 teid, u32 local_ip, u16 local_port)
{
    memset(key, 0, sizeof(*key));
    key->teid = teid;
    key->local_ip = local_ip;
    key->local_port = local_port;
}

static inline void gtpu_fill_socket_key(gtpu_socket_key_t *key, const gtpu_socket_t *gtpu_socket)
{
    gtpu_fill_key(key, gtpu_socket->incoming_teid, gtpu_socket->local.ip, gtpu_socket->local.port);
}

static inline void gtpu_fill_ldp_peer_key(gtpu_socket_key_t *key, const gtpu_socket_t *gtpu_socket)
{
    gtpu_fill_key(key, gtpu_socket->outgoing_teid, gtpu_socket->remote.ip, gtpu_socket->remote.port);
}

static void gtpu_format_name(gtpu_socket_t *gtpu_socket)
{
    char *local_ip = fnp_ipv4_ntos(gtpu_socket->local.ip);
    char *remote_ip = fnp_ipv4_ntos(gtpu_socket->remote.ip);
    snprintf(gtpu_socket->socket.name,
             sizeof(gtpu_socket->socket.name),
             "GTPU-%s:%u/%#x->%s:%u/%#x",
             local_ip == NULL ? "0.0.0.0" : local_ip,
             rte_be_to_cpu_16(gtpu_socket->local.port),
             gtpu_socket->incoming_teid,
             remote_ip == NULL ? "0.0.0.0" : remote_ip,
             rte_be_to_cpu_16(gtpu_socket->remote.port),
             gtpu_socket->outgoing_teid);
    fnp_string_free(local_ip);
    fnp_string_free(remote_ip);
}

static bool gtpu_can_pair_ldp(const gtpu_socket_t *first, const gtpu_socket_t *second)
{
    if (first == NULL || second == NULL || first == second)
    {
        return false;
    }

    if (!is_local_ipaddr(first->remote.ip) || !is_local_ipaddr(second->remote.ip))
    {
        return false;
    }

    return first->incoming_teid == second->outgoing_teid &&
           first->outgoing_teid == second->incoming_teid &&
           first->local.ip == second->remote.ip &&
           first->remote.ip == second->local.ip &&
           first->local.port == second->remote.port &&
           first->remote.port == second->local.port;
}

static bool gtpu_port_in_managed_range(u16 local_port)
{
    u16 local_port_host = rte_be_to_cpu_16(local_port);
    return local_port_host >= GTPU_AUTO_PORT_FIRST && local_port_host <= GTPU_AUTO_PORT_LAST;
}

static gtpu_port_pool_t *gtpu_get_or_create_port_pool(u32 local_ip)
{
    if (local_ip == 0)
    {
        return NULL;
    }

    gtpu_port_pool_t *pool = NULL;
    if (rte_hash_lookup_data(gtpu_context.port_pool_tbl, &local_ip, (void **)&pool) == 0)
    {
        return pool;
    }

    rte_spinlock_lock(&gtpu_context.port_pool_lock);
    if (rte_hash_lookup_data(gtpu_context.port_pool_tbl, &local_ip, (void **)&pool) < 0)
    {
        pool = fnp_zmalloc(sizeof(*pool));
        if (pool != NULL)
        {
            pool->local_ip = local_ip;
            rte_spinlock_init(&pool->lock);
            if (rte_hash_add_key_data(gtpu_context.port_pool_tbl, &pool->local_ip, pool) < 0)
            {
                fnp_free(pool);
                pool = NULL;
            }
        }
    }
    rte_spinlock_unlock(&gtpu_context.port_pool_lock);

    return pool;
}

static bool gtpu_reserve_local_port(u32 local_ip, u16 local_port)
{
    if (local_ip == 0 || !gtpu_port_in_managed_range(local_port))
    {
        return true;
    }

    gtpu_port_pool_t *pool = gtpu_get_or_create_port_pool(local_ip);
    if (pool == NULL)
    {
        return false;
    }

    u16 port_offset = (u16)(rte_be_to_cpu_16(local_port) - GTPU_AUTO_PORT_FIRST);
    u32 word_index = port_offset / 64u;
    u32 bit_index = port_offset % 64u;
    u64 bit = 1ULL << bit_index;

    bool reserved = false;
    rte_spinlock_lock(&pool->lock);
    if ((pool->used_bitmap[word_index] & bit) == 0)
    {
        pool->used_bitmap[word_index] |= bit;
        reserved = true;
    }
    rte_spinlock_unlock(&pool->lock);

    return reserved;
}

static void gtpu_release_local_port(const gtpu_socket_t *gtpu_socket)
{
    if (gtpu_socket == NULL || gtpu_socket->local.ip == 0 || !gtpu_port_in_managed_range(gtpu_socket->local.port))
    {
        return;
    }

    gtpu_port_pool_t *pool = NULL;
    if (rte_hash_lookup_data(gtpu_context.port_pool_tbl, &gtpu_socket->local.ip, (void **)&pool) < 0 || pool == NULL)
    {
        return;
    }

    u16 port_offset = (u16)(rte_be_to_cpu_16(gtpu_socket->local.port) - GTPU_AUTO_PORT_FIRST);
    u32 word_index = port_offset / 64u;
    u32 bit_index = port_offset % 64u;
    u64 bit = 1ULL << bit_index;

    rte_spinlock_lock(&pool->lock);
    pool->used_bitmap[word_index] &= ~bit;
    if (port_offset < pool->next_port_offset)
    {
        pool->next_port_offset = port_offset;
    }
    rte_spinlock_unlock(&pool->lock);
}

static u16 gtpu_allocate_auto_local_port(u32 local_ip)
{
    if (local_ip == 0)
    {
        return 0;
    }

    gtpu_port_pool_t *pool = gtpu_get_or_create_port_pool(local_ip);
    if (pool == NULL)
    {
        return 0;
    }

    rte_spinlock_lock(&pool->lock);
    for (u32 scanned = 0; scanned < GTPU_AUTO_PORT_COUNT; ++scanned)
    {
        u16 offset = (u16)((pool->next_port_offset + scanned) % GTPU_AUTO_PORT_COUNT);
        u32 word_index = offset / 64u;
        u32 bit_index = offset % 64u;
        u64 bit = 1ULL << bit_index;
        if ((pool->used_bitmap[word_index] & bit) != 0)
        {
            continue;
        }

        pool->used_bitmap[word_index] |= bit;
        pool->next_port_offset = (u16)((offset + 1u) % GTPU_AUTO_PORT_COUNT);
        rte_spinlock_unlock(&pool->lock);
        return rte_cpu_to_be_16((u16)(GTPU_AUTO_PORT_FIRST + offset));
    }

    rte_spinlock_unlock(&pool->lock);
    return 0;
}

static fnp_ifaddr_t *gtpu_pick_frontend_ifaddr(const fnp_frontend_t *frontend,
                                               const fnp_route_result_t *route_result)
{
    if (frontend == NULL || route_result == NULL || frontend->ifaddr_count == 0)
    {
        return NULL;
    }

    fnp_ifaddr_t *same_pref = NULL;
    fnp_ifaddr_t *same_network = NULL;
    fnp_ifaddr_t *same_device = NULL;
    fnp_ifaddr_t *first = NULL;
    for (u16 i = 0; i < frontend->ifaddr_count; ++i)
    {
        fnp_ifaddr_t *candidate = lookup_ifaddr(frontend->ifaddrs[i].ip);
        if (candidate == NULL)
        {
            continue;
        }

        if (first == NULL)
        {
            first = candidate;
        }

        if (candidate->local_ip_be == route_result->pref_src_be)
        {
            same_pref = candidate;
            break;
        }

        if (route_result->ifaddr != NULL &&
            candidate->network_be == route_result->ifaddr->network_be &&
            candidate->netmask_be == route_result->ifaddr->netmask_be &&
            candidate->local_ip_be != route_result->ifaddr->local_ip_be &&
            same_network == NULL)
        {
            same_network = candidate;
        }

        if (route_result->ifaddr != NULL &&
            candidate->dev == route_result->ifaddr->dev &&
            candidate->local_ip_be != route_result->ifaddr->local_ip_be &&
            same_device == NULL)
        {
            same_device = candidate;
        }
    }

    if (same_pref != NULL)
    {
        return same_pref;
    }

    if (same_network != NULL)
    {
        return same_network;
    }

    if (same_device != NULL)
    {
        return same_device;
    }

    return first;
}

static int gtpu_resolve_send_addr(const fnp_gtpu_socket_conf_t *gtpu_conf,
                                  const fnp_frontend_t *frontend,
                                  fsockaddr_t *local)
{
    if (gtpu_conf == NULL || local == NULL)
    {
        return FNP_ERR_PARAM;
    }

    memset(local, 0, sizeof(*local));
    local->family = FSOCKADDR_IPV4;
    local->ip = gtpu_conf->send_ip;
    local->port = gtpu_conf->send_port;
    if (local->ip == 0)
    {
        fnp_route_result_t route_result;
        int ret = route_lookup(gtpu_conf->remote.ip, &route_result);
        if (ret != FNP_OK || route_result.ifaddr == NULL)
        {
            return ret != FNP_OK ? ret : FNP_ERR_NOT_FOUND;
        }

        fnp_ifaddr_t *preferred_ifaddr = gtpu_pick_frontend_ifaddr(frontend, &route_result);
        local->ip = preferred_ifaddr == NULL ? route_result.pref_src_be : preferred_ifaddr->local_ip_be;
    }
    else if (lookup_ifaddr(local->ip) == NULL)
    {
        return FNP_ERR_IFACE_NOT_FOUND;
    }

    if (local->port == 0)
    {
        local->port = gtpu_allocate_auto_local_port(local->ip);
        if (local->port == 0)
        {
            return FNP_ERR_FULL;
        }
    }
    else if (!gtpu_reserve_local_port(local->ip, local->port))
    {
        return FNP_ERR_PORT_BIND;
    }

    return FNP_OK;
}

static void gtpu_try_pair_ldp(gtpu_socket_t *gtpu_socket)
{
    if (gtpu_socket == NULL || gtpu_socket->ldp_peer != NULL)
    {
        return;
    }

    gtpu_socket_key_t peer_key;
    gtpu_fill_ldp_peer_key(&peer_key, gtpu_socket);

    fsocket_t *peer_socket = NULL;
    if (rte_hash_lookup_data(gtpu_context.global_tbl, &peer_key, (void **)&peer_socket) < 0 || peer_socket == NULL)
    {
        return;
    }

    gtpu_socket_t *peer = gtpu_socket_cast(peer_socket);
    if (!peer->is_registered || peer->ldp_peer != NULL || !gtpu_can_pair_ldp(gtpu_socket, peer))
    {
        return;
    }

    gtpu_socket->ldp_peer = peer;
    peer->ldp_peer = gtpu_socket;
    // 先写地址字段（非原子），再用 release store 发布 peer 指针，
    // 保证前端见到非 NULL peer 时地址字段已经可见。
    fsockaddr_copy(&gtpu_socket->socket.direct_local, &peer->local);
    fsockaddr_copy(&gtpu_socket->socket.direct_remote, &peer->remote);
    fsockaddr_copy(&peer->socket.direct_local, &gtpu_socket->local);
    fsockaddr_copy(&peer->socket.direct_remote, &gtpu_socket->remote);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    fsocket_direct_peer_store(&gtpu_socket->socket, &peer->socket);
    fsocket_direct_peer_store(&peer->socket, &gtpu_socket->socket);
}

static void gtpu_clear_direct_path(gtpu_socket_t *gtpu_socket)
{
    if (gtpu_socket == NULL)
    {
        return;
    }

    fsocket_direct_peer_store(&gtpu_socket->socket, NULL);
    memset(&gtpu_socket->socket.direct_local, 0, sizeof(gtpu_socket->socket.direct_local));
    memset(&gtpu_socket->socket.direct_remote, 0, sizeof(gtpu_socket->socket.direct_remote));
}

static void gtpu_remove_from_recv_worker(gtpu_socket_t *gtpu_socket)
{
    if (gtpu_socket == NULL || gtpu_socket->socket.recv_worker_id < 0)
    {
        return;
    }

    fnp_worker_t *worker = get_fnp_worker(gtpu_socket->socket.recv_worker_id);
    if (worker == NULL || worker->gtpu_rx_tbl == NULL)
    {
        gtpu_socket->socket.recv_worker_id = -1;
        return;
    }

    gtpu_socket_key_t key;
    gtpu_fill_socket_key(&key, gtpu_socket);
    rte_hash_del_key(worker->gtpu_rx_tbl, &key);
    if (worker->recv_socket_count > 0)
    {
        worker->recv_socket_count--;
    }
    gtpu_socket->socket.recv_worker_id = -1;
}

static void gtpu_learn_recv_worker(gtpu_socket_t *gtpu_socket, fnp_worker_t *worker, const gtpu_socket_key_t *key)
{
    if (gtpu_socket == NULL || key == NULL || worker == NULL || worker->gtpu_rx_tbl == NULL)
    {
        return;
    }

    int worker_id = worker->id;

    rte_spinlock_lock(&gtpu_context.lock);
    if (!gtpu_socket->is_registered)
    {
        rte_spinlock_unlock(&gtpu_context.lock);
        return;
    }

    if (gtpu_socket->socket.recv_worker_id == worker_id)
    {
        rte_spinlock_unlock(&gtpu_context.lock);
        return;
    }

    gtpu_remove_from_recv_worker(gtpu_socket);
    if (rte_hash_add_key_data(worker->gtpu_rx_tbl, key, &gtpu_socket->socket) >= 0)
    {
        gtpu_socket->socket.recv_worker_id = worker_id;
        worker->recv_socket_count++;
    }
    rte_spinlock_unlock(&gtpu_context.lock);
}

static fsocket_t *gtpu_lookup_socket(u32 teid, u32 local_ip, u16 local_port)
{
    gtpu_socket_key_t key;
    gtpu_fill_key(&key, teid, local_ip, local_port);

    fnp_worker_t *worker = get_local_worker();
    fsocket_t *socket = NULL;
    if (likely(worker != NULL && worker->gtpu_rx_tbl != NULL &&
               rte_hash_lookup_data(worker->gtpu_rx_tbl, &key, (void **)&socket) == 0 && socket != NULL))
    {
        return fsocket_acquire_active(socket);
    }

    if (unlikely(rte_hash_lookup_data(gtpu_context.global_tbl, &key, (void **)&socket) < 0 || socket == NULL))
    {
        return NULL;
    }

    socket = fsocket_acquire_active(socket);
    if (socket == NULL)
    {
        return NULL;
    }

    if (worker != NULL && worker->gtpu_rx_tbl != NULL)
    {
        gtpu_learn_recv_worker(gtpu_socket_cast(socket), worker, &key);
    }

    return socket;
}

static int gtpu_socket_register(gtpu_socket_t *gtpu_socket)
{
    if (gtpu_socket == NULL || gtpu_socket->incoming_teid == 0)
    {
        return FNP_ERR_PARAM;
    }

    gtpu_socket_key_t key;
    gtpu_fill_socket_key(&key, gtpu_socket);

    rte_spinlock_lock(&gtpu_context.lock);
    if (rte_hash_add_key_data(gtpu_context.global_tbl,
                              &key,
                              &gtpu_socket->socket) < 0)
    {
        rte_spinlock_unlock(&gtpu_context.lock);
        return FNP_ERR_ADD_HASH;
    }

    gtpu_socket->is_registered = true;
    gtpu_try_pair_ldp(gtpu_socket);
    rte_spinlock_unlock(&gtpu_context.lock);
    return FNP_OK;
}

static void gtpu_socket_unregister(gtpu_socket_t *gtpu_socket)
{
    if (gtpu_socket == NULL || !gtpu_socket->is_registered)
    {
        return;
    }

    gtpu_socket_key_t key;
    gtpu_fill_socket_key(&key, gtpu_socket);

    rte_spinlock_lock(&gtpu_context.lock);
    rte_hash_del_key(gtpu_context.global_tbl, &key);
    gtpu_remove_from_recv_worker(gtpu_socket);
    if (gtpu_socket->ldp_peer != NULL)
    {
        gtpu_socket->ldp_peer->ldp_peer = NULL;
        gtpu_clear_direct_path(gtpu_socket->ldp_peer);
        gtpu_socket->ldp_peer = NULL;
    }
    gtpu_clear_direct_path(gtpu_socket);
    gtpu_socket->is_registered = false;
    rte_spinlock_unlock(&gtpu_context.lock);
}

static inline void gtpu_prepend_hdr(struct rte_mbuf *m, u32 teid, u16 payload_len)
{
    gtpu_hdr_t *hdr = (gtpu_hdr_t *)rte_pktmbuf_prepend(m, GTPU_HDR_LEN);
    hdr->flags = GTPU_FLAGS_V1_GPDU;
    hdr->msg_type = GTPU_MSGTYPE_GPDU;
    hdr->msg_length = rte_cpu_to_be_16(payload_len);
    hdr->teid = rte_cpu_to_be_32(teid);
}

static inline void gtpu_prepend_udp_hdr(struct rte_mbuf *m, u16 src_port, u16 dst_port)
{
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_udp_hdr));
    hdr->src_port = src_port;
    hdr->dst_port = dst_port;
    hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len);
    hdr->dgram_cksum = 0;
}

static void gtpu_socket_recv(fsocket_t *socket, struct rte_mbuf *m)
{
    if (unlikely(!fsocket_enqueue_for_app(socket, m)))
    {
        free_mbuf(m);
    }

    fsocket_ref_put(socket);
}

static inline void gtpu_socket_send_network(gtpu_socket_t *gtpu_socket, struct rte_mbuf *m)
{
    u16 payload_len = (u16)m->pkt_len;
    gtpu_prepend_hdr(m, gtpu_socket->outgoing_teid, payload_len);
    gtpu_prepend_udp_hdr(m, gtpu_socket->local.port, gtpu_socket->remote.port);
    ipv4_tx_cache_send(&gtpu_socket->tx_cache,
                       m,
                       IPPROTO_UDP,
                       &gtpu_socket->local,
                       &gtpu_socket->remote);
}

static void gtpu_socket_send(fsocket_t *socket, u64 tsc)
{
    struct rte_mbuf *mbufs[GTPU_BURST_SIZE] = {0};
    u32 n = fnp_ring_dequeue_burst(socket->tx, (void **)mbufs, GTPU_BURST_SIZE);
    gtpu_socket_t *gtpu_socket = gtpu_socket_cast(socket);
    for (u32 i = 0; i < n; ++i)
    {
        gtpu_socket_send_network(gtpu_socket, mbufs[i]);
    }

    if (n > 0)
    {
        socket->polling_tsc = tsc;
    }
}

static void gtpu_socket_release(fsocket_t *socket)
{
    gtpu_socket_t *gtpu_socket = gtpu_socket_cast(socket);

    fsocket_cleanup(socket);
    fnp_free(gtpu_socket);
}

static void gtpu_socket_release_when_idle(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return;
    }

    if (fsocket_ref_count(socket) > 1)
    {
        if (fnp_master_retire_fsocket(socket, gtpu_socket_release_when_idle) == FNP_OK)
        {
            return;
        }

        while (fsocket_ref_count(socket) > 1)
        {
            rte_pause();
        }
    }

    gtpu_socket_release(socket);
}

static void gtpu_socket_close(fsocket_t *socket)
{
    gtpu_socket_t *gtpu_socket = gtpu_socket_cast(socket);
    fsocket_enter_closing(socket);
    gtpu_socket_unregister(gtpu_socket);
    gtpu_release_local_port(gtpu_socket);
    fsocket_mark_closed(socket);

    if (fnp_master_retire_fsocket(socket, gtpu_socket_release_when_idle) == FNP_OK)
    {
        return;
    }

    (void)fnp_master_remove_fsocket(socket);
    gtpu_socket_release_when_idle(socket);
}

static fsocket_t *gtpu_socket_create(void *conf, void *ctx)
{
    const fnp_gtpu_socket_conf_t *gtpu_conf = conf;
    const fnp_frontend_t *frontend = ctx;
    if (unlikely(gtpu_conf == NULL || gtpu_conf->remote.ip == 0 ||
                 gtpu_conf->incoming_teid == 0 || gtpu_conf->outgoing_teid == 0))
    {
        return NULL;
    }

    gtpu_socket_t *gtpu_socket = fnp_zmalloc(sizeof(*gtpu_socket));
    if (unlikely(gtpu_socket == NULL))
    {
        return NULL;
    }

    fsocket_t *socket = &gtpu_socket->socket;
    fsocket_init_base(socket, fsocket_type_gtpu);

    fsockaddr_t resolved_local = {0};
    if (gtpu_resolve_send_addr(gtpu_conf, frontend, &resolved_local) != FNP_OK)
    {
        fnp_free(gtpu_socket);
        return NULL;
    }

    fsockaddr_copy(&gtpu_socket->local, &resolved_local);
    fsockaddr_copy(&gtpu_socket->remote, &gtpu_conf->remote);
    gtpu_socket->local.family = FSOCKADDR_IPV4;
    gtpu_socket->remote.family = FSOCKADDR_IPV4;
    if (gtpu_socket->remote.port == 0)
    {
        gtpu_socket->remote.port = rte_cpu_to_be_16(FNP_GTPU_UDP_PORT);
    }
    gtpu_socket->incoming_teid = gtpu_conf->incoming_teid;
    gtpu_socket->outgoing_teid = gtpu_conf->outgoing_teid;
    socket->is_ready = 1;
    if (frontend != NULL && frontend->pool_worker_id != (u16)-1)
    {
        fsocket_set_owner_worker(socket, frontend->pool_worker_id);
    }
    ipv4_tx_cache_init(&gtpu_socket->tx_cache);
    gtpu_format_name(gtpu_socket);

    if (fsocket_create_io_rings(socket, false) != FNP_OK)
    {
        gtpu_socket_close(socket);
        return NULL;
    }

    if (gtpu_socket_register(gtpu_socket) != FNP_OK)
    {
        gtpu_socket_close(socket);
        return NULL;
    }

    printf("create socket %s\n", socket->name);
    return socket;
}

static const fsocket_ops_t gtpu_fsocket_ops = {
    .create = gtpu_socket_create,
    .close = gtpu_socket_close,
    .send = gtpu_socket_send,
    .recv = gtpu_socket_recv,
};

void gtpu_udp_input(struct rte_mbuf *m)
{
    if (unlikely(m == NULL || m->pkt_len < sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + GTPU_HDR_LEN))
    {
        free_mbuf(m);
        return;
    }

    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u16 iphdr_len = rte_ipv4_hdr_len(ip_hdr);
    u16 udp_offset = iphdr_len;
    u16 decap_len = udp_offset + sizeof(struct rte_udp_hdr) + GTPU_HDR_LEN;
    if (unlikely(m->pkt_len < decap_len))
    {
        free_mbuf(m);
        return;
    }

    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, iphdr_len);
    u16 udp_len = rte_be_to_cpu_16(udp_hdr->dgram_len);
    if (unlikely(udp_len < sizeof(struct rte_udp_hdr) + GTPU_HDR_LEN))
    {
        free_mbuf(m);
        return;
    }

    u16 payload_bytes = udp_len - sizeof(struct rte_udp_hdr) - GTPU_HDR_LEN;
    gtpu_hdr_t *gtpu_hdr = rte_pktmbuf_mtod_offset(m, gtpu_hdr_t *, udp_offset + sizeof(struct rte_udp_hdr));
    if (unlikely(gtpu_hdr->flags != GTPU_FLAGS_V1_GPDU || gtpu_hdr->msg_type != GTPU_MSGTYPE_GPDU))
    {
        free_mbuf(m);
        return;
    }

    u16 gtpu_payload_len = rte_be_to_cpu_16(gtpu_hdr->msg_length);
    if (unlikely(gtpu_payload_len > payload_bytes))
    {
        free_mbuf(m);
        return;
    }

    u32 incoming_teid = rte_be_to_cpu_32(gtpu_hdr->teid);
    fsocket_t *socket = gtpu_lookup_socket(incoming_teid, ip_hdr->dst_addr, udp_hdr->dst_port);
    if (unlikely(socket == NULL))
    {
        free_mbuf(m);
        return;
    }

    rte_pktmbuf_adj(m, decap_len);
    int trim_len = rte_pktmbuf_data_len(m) - (int)gtpu_payload_len;
    if (trim_len > 0)
    {
        rte_pktmbuf_trim(m, trim_len);
    }

    fmbuf_info_t *info = get_fmbuf_info(m);
    info->local.family = FSOCKADDR_IPV4;
    info->local.ip = ip_hdr->dst_addr;
    info->local.port = udp_hdr->dst_port;
    info->remote.family = FSOCKADDR_IPV4;
    info->remote.ip = ip_hdr->src_addr;
    info->remote.port = udp_hdr->src_port;

    gtpu_socket_recv(socket, m);
}

int gtpu_export_socket_conf(const fsocket_t *socket, fnp_gtpu_socket_conf_t *conf)
{
    if (socket == NULL || conf == NULL || socket->type != fsocket_type_gtpu)
    {
        return FNP_ERR_PARAM;
    }

    const gtpu_socket_t *gtpu_socket = (const gtpu_socket_t *)socket;
    memset(conf, 0, sizeof(*conf));
    conf->send_ip = gtpu_socket->local.ip;
    conf->send_port = gtpu_socket->local.port;
    fsockaddr_copy(&conf->remote, &gtpu_socket->remote);
    conf->incoming_teid = gtpu_socket->incoming_teid;
    conf->outgoing_teid = gtpu_socket->outgoing_teid;
    return FNP_OK;
}

int gtpu_module_init(void)
{
    int ret = gtpu_init_context();
    CHECK_RET(ret);

    ret = register_fsocket_ops(fsocket_type_gtpu, &gtpu_fsocket_ops);
    CHECK_RET(ret);

    return ipv4_register_input(IPPROTO_UDP, gtpu_udp_input);
}