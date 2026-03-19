#include "udp.h"

#include "fnp.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_network.h"
#include "fnp_worker.h"
#include "icmp.h"
#include "ipv4.h"

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <string.h>

#define FNP_UDP_HDR_LEN 8
#define UDP_SOCKET_TABLE_SIZE 1024

typedef struct udp_socket
{
    fsocket_t socket;
    fsockaddr_t local;
    fsockaddr_t remote;
    bool is_registered;
} udp_socket_t;

typedef struct udp_socket_key_4tuple
{
    u32 local_ip;
    u32 remote_ip;
    u16 local_port;
    u16 remote_port;
} udp_socket_key_4tuple_t;

typedef struct udp_socket_key_2tuple
{
    u32 local_ip;
    u16 local_port;
    u16 reserved0;
} udp_socket_key_2tuple_t;

typedef struct udp_context
{
    struct rte_hash *socket_4tuple_tbl;
    struct rte_hash *socket_2tuple_tbl;
} udp_context_t;

static udp_context_t udp_context;

static void udp_socket_close(fsocket_t *socket);

static inline const udp_socket_t *udp_socket_const(const fsocket_t *socket)
{
    return (const udp_socket_t *)socket;
}

static inline udp_socket_t *udp_socket_cast(fsocket_t *socket)
{
    return (udp_socket_t *)socket;
}

static inline const fsockaddr_t *udp_socket_local_addr_const(const fsocket_t *socket)
{
    return &udp_socket_const(socket)->local;
}

static inline const fsockaddr_t *udp_socket_remote_addr_const(const fsocket_t *socket)
{
    return &udp_socket_const(socket)->remote;
}

static inline bool udp_socket_is_connected(const fsocket_t *socket)
{
    const fsockaddr_t *remote = udp_socket_remote_addr_const(socket);
    return remote->ip != 0 || remote->port != 0;
}

static inline bool udp_remote_matches(const fsocket_t *socket, const fsockaddr_t *remote)
{
    return fsockaddr_compare(udp_socket_remote_addr_const(socket), remote);
}

static inline void udp_init_4tuple_key(udp_socket_key_4tuple_t *key,
                                       const fsockaddr_t *local,
                                       const fsockaddr_t *remote)
{
    memset(key, 0, sizeof(*key));
    key->local_ip = local->ip;
    key->remote_ip = remote->ip;
    key->local_port = local->port;
    key->remote_port = remote->port;
}

static inline void udp_init_2tuple_key(udp_socket_key_2tuple_t *key, const fsockaddr_t *local)
{
    memset(key, 0, sizeof(*key));
    key->local_ip = local->ip;
    key->local_port = local->port;
}

static struct rte_hash *udp_create_hash_table(const char *name, u32 entries, u32 key_len)
{
    struct rte_hash_parameters params = {
        .name = name,
        .entries = entries,
        .key_len = key_len,
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };

    return rte_hash_create(&params);
}

static int udp_init_context(void)
{
    udp_context.socket_4tuple_tbl = udp_create_hash_table("fnp_udp_socket_4tuple_tbl",
                                                          UDP_SOCKET_TABLE_SIZE,
                                                          sizeof(udp_socket_key_4tuple_t));
    if (udp_context.socket_4tuple_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    udp_context.socket_2tuple_tbl = udp_create_hash_table("fnp_udp_socket_2tuple_tbl",
                                                          UDP_SOCKET_TABLE_SIZE,
                                                          sizeof(udp_socket_key_2tuple_t));
    if (udp_context.socket_2tuple_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    return FNP_OK;
}

static fsocket_t *udp_lookup_4tuple(const fsockaddr_t *local, const fsockaddr_t *remote)
{
    udp_socket_key_4tuple_t key;
    fsocket_t *socket = NULL;

    udp_init_4tuple_key(&key, local, remote);
    if (rte_hash_lookup_data(udp_context.socket_4tuple_tbl, &key, (void **)&socket) < 0)
    {
        return NULL;
    }

    return socket;
}

static fsocket_t *udp_lookup_2tuple(const fsockaddr_t *local)
{
    udp_socket_key_2tuple_t key;
    fsocket_t *socket = NULL;

    udp_init_2tuple_key(&key, local);
    if (rte_hash_lookup_data(udp_context.socket_2tuple_tbl, &key, (void **)&socket) < 0)
    {
        return NULL;
    }

    return socket;
}

static fsocket_t *udp_lookup_2tuple_with_remote(const fsockaddr_t *local, const fsockaddr_t *remote)
{
    fsocket_t *socket = udp_lookup_2tuple(local);
    if (socket == NULL)
    {
        return NULL;
    }

    if (!udp_socket_is_connected(socket) || udp_remote_matches(socket, remote))
    {
        return socket;
    }

    return NULL;
}

static fsocket_t *udp_socket_lookup(const fsockaddr_t *local, const fsockaddr_t *remote)
{
    fsocket_t *socket = udp_lookup_4tuple(local, remote);
    if (socket != NULL)
    {
        return socket;
    }

    socket = udp_lookup_2tuple_with_remote(local, remote);
    if (socket != NULL)
    {
        return socket;
    }

    if (local->ip == 0)
    {
        return NULL;
    }

    fsockaddr_t wildcard_local = *local;
    wildcard_local.ip = 0;
    return udp_lookup_2tuple_with_remote(&wildcard_local, remote);
}

static bool udp_has_specific_bind_on_port(u16 local_port)
{
    uint32_t next = 0;
    const void *key = NULL;
    fsocket_t *socket = NULL;

    while (rte_hash_iterate(udp_context.socket_2tuple_tbl, &key, (void **)&socket, &next) >= 0)
    {
        const udp_socket_key_2tuple_t *tuple_key = key;
        if (tuple_key->local_port == local_port && tuple_key->local_ip != 0)
        {
            return true;
        }
    }

    return false;
}

static bool udp_socket_has_bind_conflict(const fsockaddr_t *local)
{
    fsockaddr_t wildcard_local = *local;
    wildcard_local.ip = 0;

    if (local->ip == 0)
    {
        if (udp_lookup_2tuple(&wildcard_local) != NULL)
        {
            return true;
        }

        return udp_has_specific_bind_on_port(local->port);
    }

    if (udp_lookup_2tuple(local) != NULL)
    {
        return true;
    }

    return udp_lookup_2tuple(&wildcard_local) != NULL;
}

static int udp_socket_register(fsocket_t *socket)
{
    const fsockaddr_t *local = udp_socket_local_addr_const(socket);
    const fsockaddr_t *remote = udp_socket_remote_addr_const(socket);
    udp_socket_key_2tuple_t key_2tuple;

    if (udp_socket_has_bind_conflict(local))
    {
        return FNP_ERR_ADD_HASH;
    }

    udp_init_2tuple_key(&key_2tuple, local);
    if (rte_hash_add_key_data(udp_context.socket_2tuple_tbl, &key_2tuple, socket) < 0)
    {
        return FNP_ERR_ADD_HASH;
    }

    if (!udp_socket_is_connected(socket))
    {
        return FNP_OK;
    }

    udp_socket_key_4tuple_t key_4tuple;
    udp_init_4tuple_key(&key_4tuple, local, remote);
    if (rte_hash_add_key_data(udp_context.socket_4tuple_tbl, &key_4tuple, socket) < 0)
    {
        rte_hash_del_key(udp_context.socket_2tuple_tbl, &key_2tuple);
        return FNP_ERR_ADD_HASH;
    }

    return FNP_OK;
}

static void udp_socket_unregister(fsocket_t *socket)
{
    const fsockaddr_t *local = udp_socket_local_addr_const(socket);

    if (socket == NULL)
    {
        return;
    }

    if (udp_socket_is_connected(socket))
    {
        udp_socket_key_4tuple_t key_4tuple;
        udp_init_4tuple_key(&key_4tuple, local, udp_socket_remote_addr_const(socket));
        rte_hash_del_key(udp_context.socket_4tuple_tbl, &key_4tuple);
    }

    udp_socket_key_2tuple_t key_2tuple;
    udp_init_2tuple_key(&key_2tuple, local);
    rte_hash_del_key(udp_context.socket_2tuple_tbl, &key_2tuple);
}

static inline void local_forward_path(fsockaddr_t *local, fsockaddr_t *remote, struct rte_mbuf *m)
{
    fsocket_t *dst_socket = udp_socket_lookup(remote, local);
    if (unlikely(dst_socket == NULL))
    {
        free_mbuf(m);
        return;
    }

    get_fsocket_ops(dst_socket->type)->recv(dst_socket, m);
}

static void udp_socket_send_one(fsocket_t *socket, struct rte_mbuf *m)
{
    fmbuf_info_t *info = get_fmbuf_info(m);
    const fsockaddr_t *local = udp_socket_local_addr_const(socket);

    if (is_local_ipaddr(info->remote.ip))
    {
        local_forward_path(&info->local, &info->remote, m);
        return;
    }

    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, FNP_UDP_HDR_LEN);
    hdr->src_port = local->port;
    hdr->dst_port = info->remote.port;
    hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len);
    hdr->dgram_cksum = 0;

    ipv4_send_mbuf(m, IPPROTO_UDP, info->remote.ip);
}

static void udp_socket_send(fsocket_t *socket, u64 tsc)
{
#define UDP_BURST_SIZE 32
    static struct rte_mbuf *mbufs[UDP_BURST_SIZE];

    u32 n = fnp_ring_dequeue_burst(socket->tx, (void **)mbufs, UDP_BURST_SIZE);
    for (u32 i = 0; i < n; ++i)
    {
        udp_socket_send_one(socket, mbufs[i]);
    }

    if (n > 0)
    {
        socket->polling_tsc = tsc;
    }
}

static void udp_socket_recv(fsocket_t *socket, struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u16 iphdr_len = rte_ipv4_hdr_len(ip_hdr);
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)rte_pktmbuf_adj(m, iphdr_len);

    rte_pktmbuf_adj(m, FNP_UDP_HDR_LEN);

    int data_len = rte_pktmbuf_data_len(m);
    int udp_data_len = rte_cpu_to_be_16(udp_hdr->dgram_len) - FNP_UDP_HDR_LEN;
    rte_pktmbuf_trim(m, data_len - udp_data_len);

    fmbuf_info_t *info = get_fmbuf_info(m);
    info->remote.family = FSOCKADDR_IPV4;
    info->remote.ip = ip_hdr->src_addr;
    info->remote.port = udp_hdr->src_port;
    info->local.family = FSOCKADDR_IPV4;
    info->local.ip = ip_hdr->dst_addr;
    info->local.port = udp_hdr->dst_port;

    if (unlikely(!fsocket_enqueue_for_app(socket, m)))
    {
        free_mbuf(m);
    }
}

static void udp_input(struct rte_mbuf *m)
{
    fsockaddr_t local = {
        .family = FSOCKADDR_IPV4,
    };
    fsockaddr_t remote = {
        .family = FSOCKADDR_IPV4,
    };

    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, rte_ipv4_hdr_len(ip_hdr));

    local.ip = ip_hdr->dst_addr;
    local.port = udp_hdr->dst_port;
    remote.ip = ip_hdr->src_addr;
    remote.port = udp_hdr->src_port;

    fsocket_t *socket = udp_socket_lookup(&local, &remote);
    if (unlikely(socket == NULL))
    {
        icmp_send_port_unreachable(m);
        free_mbuf(m);
        return;
    }

    get_fsocket_ops(socket->type)->recv(socket, m);
}

static fsocket_t *udp_socket_create(void *conf)
{
    const fnp_udp_socket_conf_t *udp_conf = conf;
    udp_socket_t *udp_socket;
    fsocket_t *socket;

    if (unlikely(udp_conf == NULL))
    {
        printf("udp_socket_create: conf is NULL\n");
        return NULL;
    }

    if (udp_conf->local.ip != 0 && lookup_ifaddr(udp_conf->local.ip) == NULL)
    {
        char* local_ip = fnp_ipv4_ntos(udp_conf->local.ip);
        printf("udp_socket_create: local ip %s is not configured on daemon\n", local_ip);
        fnp_string_free(local_ip);
        return NULL;
    }

    udp_socket = fnp_zmalloc(sizeof(*udp_socket));
    if (udp_socket == NULL)
    {
        printf("udp_socket_create: fail to alloc udp_socket\n");
        return NULL;
    }

    socket = &udp_socket->socket;
    fsocket_init_base(socket, fsocket_type_udp);
    fsockaddr_copy(&udp_socket->local, &udp_conf->local);
    fsockaddr_copy(&udp_socket->remote, &udp_conf->remote);
    udp_socket->local.family = FSOCKADDR_IPV4;
    udp_socket->remote.family = FSOCKADDR_IPV4;
    fsocket_format_transport_name(socket, "UDP", &udp_socket->local, &udp_socket->remote);

    if (udp_socket_register(socket) != FNP_OK)
    {
        printf("udp_socket_create: bind/register failed for %s\n", socket->name);
        udp_socket_close(socket);
        return NULL;
    }
    udp_socket->is_registered = true;

    if (fsocket_create_io_rings(socket, udp_socket->remote.ip == 0) != FNP_OK)
    {
        printf("udp_socket_create: fail to create io rings for %s\n", socket->name);
        udp_socket_close(socket);
        return NULL;
    }

    printf("create socket %s\n", socket->name);
    return socket;
}

static void udp_socket_close(fsocket_t *socket)
{
    udp_socket_t *udp_socket = (udp_socket_t *)socket;
    if (udp_socket->is_registered)
    {
        udp_socket_unregister(socket);
        udp_socket->is_registered = false;
    }

    fsocket_cleanup(socket);
    fnp_free(udp_socket);
}

static const fsocket_ops_t udp_fsocket_ops = {
    .create = udp_socket_create,
    .close = udp_socket_close,
    .send = udp_socket_send,
    .recv = udp_socket_recv,
};

int udp_module_init(void)
{
    int ret = udp_init_context();
    CHECK_RET(ret);

    ret = register_fsocket_ops(fsocket_type_udp, &udp_fsocket_ops);
    CHECK_RET(ret);

    return ipv4_register_input(IPPROTO_UDP, udp_input);
}
