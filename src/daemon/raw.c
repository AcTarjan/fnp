#include "raw.h"

#include "fnp.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_network.h"
#include "fnp_worker.h"
#include "ipv4.h"

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_rwlock.h>
#include <string.h>

#define RAW_SOCKET_BURST_SIZE 32
#define RAW_SOCKET_TABLE_SIZE 1024

typedef struct raw_socket
{
    fsocket_t socket;
    struct raw_socket *next;
    fsockaddr_t local;
    u16 device_id;
    u8 protocol;
    u8 reserved0;
    bool is_registered;
} raw_socket_t;

typedef struct raw_socket_exact_key
{
    u8 protocol;
    u8 reserved0;
    u16 reserved1;
    u32 local_ip;
} raw_socket_exact_key_t;

typedef enum raw_match_type
{
    raw_match_type_invalid = 0,
    raw_match_type_protocol_ip,
    raw_match_type_protocol,
    raw_match_type_ip,
} raw_match_type_t;

typedef struct raw_context
{
    struct rte_hash *socket_tbl;
    rte_rwlock_t lock;
    u32 socket_count;
} raw_context_t;

static raw_context_t raw_context;

static inline const raw_socket_t *raw_socket_const(const fsocket_t *socket)
{
    return (const raw_socket_t *)socket;
}

static inline const fsockaddr_t *raw_socket_local_addr_const(const fsocket_t *socket)
{
    return &raw_socket_const(socket)->local;
}

static inline u8 raw_socket_protocol_const(const fsocket_t *socket)
{
    return raw_socket_const(socket)->protocol;
}

static inline u16 raw_socket_device_id_const(const fsocket_t *socket)
{
    return raw_socket_const(socket)->device_id;
}

static inline void raw_init_exact_key(raw_socket_exact_key_t *key, u8 protocol, u32 local_ip)
{
    memset(key, 0, sizeof(*key));
    key->protocol = protocol;
    key->local_ip = local_ip;
}

static struct rte_hash *raw_create_hash(const char *name, u32 key_len)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = RAW_SOCKET_TABLE_SIZE,
        .key_len = key_len,
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    return rte_hash_create(&params);
}

static int raw_init_context(void)
{
    if (raw_context.socket_tbl != NULL)
    {
        return FNP_OK;
    }

    raw_context.socket_tbl = raw_create_hash("fnp_raw_socket_tbl", sizeof(raw_socket_exact_key_t));
    if (raw_context.socket_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    rte_rwlock_init(&raw_context.lock);
    raw_context.socket_count = 0;
    return FNP_OK;
}

static raw_match_type_t raw_match_type_from_values(u8 protocol, u32 local_ip)
{
    if (protocol != 0 && local_ip != 0)
    {
        return raw_match_type_protocol_ip;
    }

    if (protocol != 0)
    {
        return raw_match_type_protocol;
    }

    if (local_ip != 0)
    {
        return raw_match_type_ip;
    }

    return raw_match_type_invalid;
}

static raw_match_type_t raw_match_type_from_socket(const fsocket_t *socket)
{
    return raw_match_type_from_values(raw_socket_protocol_const(socket), raw_socket_local_addr_const(socket)->ip);
}

static raw_socket_t *raw_lookup_head_locked(u8 protocol, u32 local_ip)
{
    raw_socket_exact_key_t key;
    raw_socket_t *head = NULL;
    raw_init_exact_key(&key, protocol, local_ip);
    return rte_hash_lookup_data(raw_context.socket_tbl, &key, (void **)&head) >= 0 ? head : NULL;
}

static int raw_update_bucket_head_locked(u8 protocol, u32 local_ip, raw_socket_t *head)
{
    raw_socket_exact_key_t key;
    raw_init_exact_key(&key, protocol, local_ip);

    if (head == NULL)
    {
        rte_hash_del_key(raw_context.socket_tbl, &key);
        return FNP_OK;
    }

    return rte_hash_add_key_data(raw_context.socket_tbl, &key, head) >= 0 ? FNP_OK : FNP_ERR_ADD_HASH;
}

static int raw_socket_register(fsocket_t *socket)
{
    raw_socket_t *raw_socket = (raw_socket_t *)socket;
    u8 protocol = raw_socket_protocol_const(socket);
    u32 local_ip = raw_socket_local_addr_const(socket)->ip;
    int ret = FNP_ERR_PARAM;

    rte_rwlock_write_lock(&raw_context.lock);
    if (raw_match_type_from_socket(socket) != raw_match_type_invalid)
    {
        raw_socket->next = raw_lookup_head_locked(protocol, local_ip);
        ret = rte_hash_add_key_data(raw_context.socket_tbl, &(raw_socket_exact_key_t){ .protocol = protocol, .local_ip = local_ip }, raw_socket) >= 0 ? FNP_OK : FNP_ERR_ADD_HASH;
        if (ret == FNP_OK)
        {
            __atomic_add_fetch(&raw_context.socket_count, 1, __ATOMIC_RELEASE);
        }
    }

    rte_rwlock_write_unlock(&raw_context.lock);
    return ret;
}

static void raw_socket_unregister(fsocket_t *socket)
{
    raw_socket_t *raw_socket = (raw_socket_t *)socket;
    raw_socket_t *head = NULL;
    raw_socket_t **current = NULL;
    u8 protocol = raw_socket_protocol_const(socket);
    u32 local_ip = raw_socket_local_addr_const(socket)->ip;

    rte_rwlock_write_lock(&raw_context.lock);
    head = raw_lookup_head_locked(protocol, local_ip);
    current = &head;
    while (*current != NULL && *current != raw_socket)
    {
        current = &(*current)->next;
    }

    if (*current == raw_socket)
    {
        *current = raw_socket->next;
        raw_update_bucket_head_locked(protocol, local_ip, head);
        __atomic_sub_fetch(&raw_context.socket_count, 1, __ATOMIC_RELEASE);
    }

    raw_socket->next = NULL;
    rte_rwlock_write_unlock(&raw_context.lock);
}

static void raw_fsocket_recv(fsocket_t *socket, struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    fmbuf_info_t *info = get_fmbuf_info(m);
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

static void raw_local_deliver(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    if (unlikely(__atomic_load_n(&raw_context.socket_count, __ATOMIC_ACQUIRE) == 0))
    {
        return;
    }

    rte_rwlock_read_lock(&raw_context.lock);

    raw_socket_t *buckets[3] = {
        raw_lookup_head_locked(hdr->next_proto_id, hdr->dst_addr),
        raw_lookup_head_locked(hdr->next_proto_id, 0),
        raw_lookup_head_locked(0, hdr->dst_addr),
    };

    for (u32 i = 0; i < 3; ++i)
    {
        for (raw_socket_t *socket = buckets[i]; socket != NULL; socket = socket->next)
        {
            struct rte_mbuf *clone = clone_mbuf(m);
            if (likely(clone != NULL))
            {
                get_fsocket_ops(socket->socket.type)->recv(&socket->socket, clone);
            }
        }
    }

    rte_rwlock_read_unlock(&raw_context.lock);
}

static void raw_socket_send_one(fsocket_t *socket, struct rte_mbuf *m)
{
    const fsockaddr_t *local = raw_socket_local_addr_const(socket);
    u8 protocol = raw_socket_protocol_const(socket);
    if (unlikely(m->pkt_len < sizeof(struct rte_ipv4_hdr)))
    {
        free_mbuf(m);
        return;
    }

    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    if (unlikely((hdr->version_ihl >> 4) != 4))
    {
        free_mbuf(m);
        return;
    }

    if (protocol != 0 && hdr->next_proto_id == 0)
    {
        hdr->next_proto_id = protocol;
    }

    if (protocol == 0 && hdr->next_proto_id == 0)
    {
        free_mbuf(m);
        return;
    }

    if (unlikely(protocol != 0 && hdr->next_proto_id != protocol))
    {
        free_mbuf(m);
        return;
    }

    if (local->ip != 0 && hdr->src_addr == 0)
    {
        hdr->src_addr = local->ip;
    }

    if (unlikely(local->ip != 0 && hdr->src_addr != local->ip))
    {
        free_mbuf(m);
        return;
    }

    ipv4_send_raw_mbuf(m);
}

static void raw_socket_send(fsocket_t *socket, u64 tsc)
{
    static struct rte_mbuf *mbufs[RAW_SOCKET_BURST_SIZE];

    u32 n = fnp_ring_dequeue_burst(socket->tx, (void **)mbufs, RAW_SOCKET_BURST_SIZE);
    for (u32 i = 0; i < n; ++i)
    {
        raw_socket_send_one(socket, mbufs[i]);
    }

    if (n > 0)
    {
        socket->polling_tsc = tsc;
    }
}

static void raw_socket_close(fsocket_t *socket)
{
    raw_socket_t *raw_socket = (raw_socket_t *)socket;
    if (raw_socket->is_registered)
    {
        raw_socket_unregister(socket);
        raw_socket->is_registered = false;
    }

    fsocket_cleanup(socket);
    fnp_free(raw_socket);
}

static fsocket_t *raw_socket_create(void *conf)
{
    const fnp_raw_socket_conf_t *raw_conf = conf;
    if (unlikely(raw_conf == NULL ||
                 raw_match_type_from_values(raw_conf->protocol, raw_conf->local_ip) == raw_match_type_invalid))
    {
        return NULL;
    }

    fnp_device_t *dev = lookup_device_by_id(raw_conf->device_id);
    if (unlikely(dev == NULL))
    {
        return NULL;
    }

    if (raw_conf->local_ip != 0)
    {
        fnp_ifaddr_t *existing_ifaddr = lookup_ifaddr(raw_conf->local_ip);
        if (existing_ifaddr == NULL)
        {
            if (add_dynamic_ifaddr(dev, raw_conf->local_ip) == NULL)
            {
                return NULL;
            }
        }
        else if (existing_ifaddr->dev != dev)
        {
            return NULL;
        }
    }

    raw_socket_t *raw_socket = fnp_zmalloc(sizeof(*raw_socket));
    if (raw_socket == NULL)
    {
        return NULL;
    }

    fsocket_t *socket = &raw_socket->socket;
    fsocket_init_base(socket, fsocket_type_raw);
    raw_socket->local.family = FSOCKADDR_IPV4;
    raw_socket->local.port = 0;
    raw_socket->local.ip = raw_conf->local_ip;
    raw_socket->device_id = raw_conf->device_id;
    raw_socket->protocol = raw_conf->protocol;

    if (raw_socket->protocol == 0)
    {
        char *local_ip = fnp_ipv4_ntos(raw_socket_local_addr_const(socket)->ip);
        snprintf(socket->name, sizeof(socket->name), "RAW-ANYPROTO-%s", local_ip);
        fnp_string_free(local_ip);
    }
    else if (raw_socket_local_addr_const(socket)->ip == 0)
    {
        snprintf(socket->name, sizeof(socket->name), "RAW-%u-ANY", raw_socket->protocol);
    }
    else
    {
        char *local_ip = fnp_ipv4_ntos(raw_socket_local_addr_const(socket)->ip);
        snprintf(socket->name, sizeof(socket->name), "RAW-%u-%s", raw_socket->protocol, local_ip);
        fnp_string_free(local_ip);
    }

    if (raw_socket_register(socket) != FNP_OK)
    {
        raw_socket_close(socket);
        return NULL;
    }
    raw_socket->is_registered = true;

    if (fsocket_create_io_rings(socket, false) != FNP_OK)
    {
        raw_socket_close(socket);
        return NULL;
    }

    printf("create socket %s\n", socket->name);
    return socket;
}

static const fsocket_ops_t raw_fsocket_ops = {
    .create = raw_socket_create,
    .close = raw_socket_close,
    .send = raw_socket_send,
    .recv = raw_fsocket_recv,
};

int raw_module_init(void)
{
    int ret = raw_init_context();
    CHECK_RET(ret);

    ret = register_fsocket_ops(fsocket_type_raw, &raw_fsocket_ops);
    CHECK_RET(ret);

    return ipv4_register_local_deliver(raw_local_deliver);
}
