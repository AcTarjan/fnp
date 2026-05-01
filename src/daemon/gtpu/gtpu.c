#include "gtpu.h"

#include "fnp.h"
#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_frontend.h"
#include "fnp_context.h"
#include "fnp_master.h"
#include "fnp_socket.h"
#include "fsocket.h"
#include "ipv4.h"
#include "route.h"
#include "fnp_worker.h"
#include "transport.h"

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_ip.h>
#include <rte_pause.h>
#include <rte_udp.h>
#include <rte_gtp.h>

#include <string.h>
#include <unistd.h>

#define GTPU_SOCKET_TABLE_SIZE 4096
#define GTPU_HDR_LEN 8
#define GTPU_FLAGS_V1_GPDU 0x30u
#define GTPU_FLAGS_V1_PT_MASK 0xf8u
#define GTPU_FLAGS_EXT 0x04u
#define GTPU_FLAGS_SEQ 0x02u
#define GTPU_FLAGS_NPDU 0x01u
#define GTPU_MSGTYPE_GPDU 255u
#define GTPU_MSGTYPE_END_MARKER 254u
#define GTPU_EXT_NONE 0u
#define GTPU_EXT_NR_RAN_CONTAINER 0x84u
#define GTPU_EXT_PDU_SESSION_CONTAINER 0x85u
#define GTPU_EXT_HDR_UNIT 4u
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

typedef struct gtpu_context
{
    transport_context_t transport; // 与应用层和IP网络层交互的传输层上下文
    u32 incoming_teid;
    u32 outgoing_teid;
    bool is_registered; // 是否已经注册到Hash表
    struct gtpu_context *ldp_peer;
} gtpu_context_t;

typedef struct gtpu_socket_key
{
    u32 teid;
    u32 local_ip;
    u16 local_port;
    u16 reserved0;
} gtpu_socket_key_t;

typedef struct gtpu_module_context
{
    struct rte_hash *global_tbl;
} gtpu_module_context_t;

static gtpu_module_context_t gtpu_module = {};
static char gtpu_local_hash_names[FNP_MAX_WORKER_NUM][64];

static void gtpu_close(transport_context_t *transport);
static void gtpu_send(transport_context_t *transport, u64 tsc);
static void gtpu_recv(transport_context_t *transport, struct rte_mbuf *m);

static const transport_ops_t gtpu_transport_ops = {
    .close = gtpu_close,
    .send = gtpu_send,
    .recv = gtpu_recv,
};

static inline gtpu_context_t *gtpu_context_cast(fsocket_t *socket)
{
    return (gtpu_context_t *)transport_from_socket(socket);
}

static void gtpu_disable_backend_tx_event(fsocket_t *socket)
{
    if (socket == NULL || socket->tx_efd_in_backend < 0)
    {
        return;
    }

    (void)fnp_master_remove_fsocket(socket);
    close(socket->tx_efd_in_backend);
    socket->tx_efd_in_backend = -1;
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
    };

    return rte_hash_create(&params);
}

static int gtpu_init_context(void)
{
    struct rte_hash_parameters params = {
        .name = "fnp_gtpu_global_tbl",
        .entries = GTPU_SOCKET_TABLE_SIZE,
        .key_len = sizeof(gtpu_socket_key_t),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
    };
    gtpu_module.global_tbl = rte_hash_create(&params);
    if (gtpu_module.global_tbl == NULL)
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
    key->teid = teid;
    key->local_ip = local_ip;
    key->local_port = local_port;
    key->reserved0 = 0;
}

static inline void gtpu_fill_socket_key(gtpu_socket_key_t *key, const gtpu_context_t *gtpu)
{
    gtpu_fill_key(key, gtpu->incoming_teid, gtpu->transport.local.ip, gtpu->transport.local.port);
}

static inline void gtpu_fill_ldp_peer_key(gtpu_socket_key_t *key, const gtpu_context_t *gtpu)
{
    gtpu_fill_key(key, gtpu->outgoing_teid, gtpu->transport.remote.ip, gtpu->transport.remote.port);
}

static void gtpu_format_name(gtpu_context_t *gtpu)
{
    fsocket_t *socket = transport_socket(&gtpu->transport);
    char *local_ip = fnp_ipv4_ntos(gtpu->transport.local.ip);
    char *remote_ip = fnp_ipv4_ntos(gtpu->transport.remote.ip);
    snprintf(socket->name,
             sizeof(socket->name),
             "GTPU-%s:%u/%#x->%s:%u/%#x",
             local_ip == NULL ? "0.0.0.0" : local_ip,
             rte_be_to_cpu_16(gtpu->transport.local.port),
             gtpu->incoming_teid,
             remote_ip == NULL ? "0.0.0.0" : remote_ip,
             rte_be_to_cpu_16(gtpu->transport.remote.port),
             gtpu->outgoing_teid);
    fnp_string_free(local_ip);
    fnp_string_free(remote_ip);
}

static bool gtpu_try_pair_ldp(gtpu_context_t *gtpu)
{
    gtpu_socket_key_t peer_key;
    gtpu_fill_ldp_peer_key(&peer_key, gtpu);

    // 查找对端socket是否存在，后建立的会配对新建立的
    gtpu_context_t *peer = NULL;
    if (rte_hash_lookup_data(gtpu_module.global_tbl, &peer_key, (void **)&peer) < 0)
    {
        return false;
    }

    // 对端socket存在，建立LDP
    fsocket_t *socket = transport_socket(&gtpu->transport);
    fsocket_t *peer_socket = transport_socket(&peer->transport);
    peer->ldp_peer = gtpu;
    gtpu->ldp_peer = peer;

    // 直接共享对端socket的队列，避免中间转发，提高性能
    socket->rx = fnp_ring_clone(peer_socket->tx);
    socket->tx = fnp_ring_clone(peer_socket->rx);
    gtpu_disable_backend_tx_event(peer_socket);
    gtpu_disable_backend_tx_event(socket);

    return true;
}

static void gtpu_remove_from_ingress_worker(gtpu_context_t *gtpu)
{
    fsocket_t *socket = gtpu == NULL ? NULL : transport_socket(&gtpu->transport);
    if (socket == NULL || socket->ingress_worker < 0)
    {
        return;
    }

    // 向ingress worker发送控制命令删除从hash表删除该socket

    fnp_worker_t *worker = get_fnp_worker(socket->ingress_worker);
    if (worker == NULL || worker->gtpu_rx_tbl == NULL)
    {
        socket->ingress_worker = -1;
        return;
    }

    gtpu_socket_key_t key;
    gtpu_fill_socket_key(&key, gtpu);
    rte_hash_del_key(worker->gtpu_rx_tbl, &key);
    if (worker->ingress_socket_count > 0)
    {
        worker->ingress_socket_count--;
    }
    socket->ingress_worker = -1;
}

static gtpu_context_t *gtpu_lookup_context(u32 teid, u32 local_ip, u16 local_port)
{
    gtpu_socket_key_t key;
    gtpu_fill_key(&key, teid, local_ip, local_port);

    fnp_worker_t *worker = get_local_worker();
    gtpu_context_t *gtpu = NULL;
    // 优先查本地worker的hash表，减少访问全局hash表的开销
    if (likely(rte_hash_lookup_data(worker->gtpu_rx_tbl, &key, (void **)&gtpu) >= 0))
    {
        return gtpu;
    }

    // 本地worker查不到，再查全局hash表
    if (unlikely(rte_hash_lookup_data(gtpu_module.global_tbl, &key, (void **)&gtpu) < 0))
    {
        return NULL;
    }

    // 从全局hash表查到，学习到本地worker的hash表，减少下次查找的开销
    if (likely(rte_hash_add_key_data(worker->gtpu_rx_tbl, &key, gtpu) >= 0))
    {
        fsocket_t *socket = transport_socket(&gtpu->transport);
        socket->ingress_worker = worker->id;
        worker->ingress_socket_count++;
    }

    return gtpu;
}

// 只会用户线程创建，不涉及并发访问，不加锁
static int gtpu_register(gtpu_context_t *gtpu)
{
    gtpu_socket_key_t key;
    gtpu_fill_socket_key(&key, gtpu);

    if (rte_hash_add_key_data(gtpu_module.global_tbl, &key, gtpu) < 0)
    {
        return FNP_ERR_ADD_HASH;
    }

    gtpu->is_registered = true;
    return FNP_OK;
}

static void gtpu_unregister(gtpu_context_t *gtpu)
{
    if (gtpu == NULL || !gtpu->is_registered)
    {
        return;
    }

    gtpu_socket_key_t key;
    gtpu_fill_socket_key(&key, gtpu);

    rte_hash_del_key(gtpu_module.global_tbl, &key);
    gtpu->is_registered = false;

    gtpu_remove_from_ingress_worker(gtpu);
    if (gtpu->ldp_peer != NULL)
    {
        gtpu->ldp_peer->ldp_peer = NULL;
        gtpu->ldp_peer = NULL;
    }
}

static inline void gtpu_prepend_hdr(struct rte_mbuf *m, u32 teid, u16 payload_len, u8 flags, u8 msg_type)
{
    gtpu_hdr_t *hdr = (gtpu_hdr_t *)rte_pktmbuf_prepend(m, GTPU_HDR_LEN);
    hdr->flags = flags;
    hdr->msg_type = msg_type;
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

static inline void gtpu_recv(transport_context_t *transport, struct rte_mbuf *m)
{
    fsocket_t *socket = transport_socket(transport);
    fsocket_enqueue_for_app(socket, m);
}

static inline bool gtpu_send_one(gtpu_context_t *gtpu, struct rte_mbuf *m)
{
    fmbuf_info_t *info = get_fmbuf_info(m);
    u16 payload_len = (u16)m->pkt_len;
    u16 gtpu_len = payload_len;
    u8 flags = GTPU_FLAGS_V1_GPDU;
    u8 msg_type = (info->gtpu_flags & FNP_MBUF_GTPU_F_MSG_TYPE) ? info->gtpu_msg_type : GTPU_MSGTYPE_GPDU;
    bool has_seq = (info->gtpu_flags & FNP_MBUF_GTPU_F_SEQ) != 0;
    bool has_npdu = (info->gtpu_flags & FNP_MBUF_GTPU_F_NPDU) != 0;
    bool has_ext = (info->gtpu_flags & FNP_MBUF_GTPU_F_EXT) != 0 && info->gtpu_ext_len > 0;

    if (has_ext)
    {
        u8 *ext = (u8 *)rte_pktmbuf_prepend(m, info->gtpu_ext_len);
        if (unlikely(ext == NULL))
        {
            free_mbuf(m);
            return false;
        }
        rte_memcpy(ext, info->gtpu_ext_data, info->gtpu_ext_len);
        gtpu_len += info->gtpu_ext_len;
        flags |= GTPU_FLAGS_EXT;
    }

    if (has_seq || has_npdu || has_ext)
    {
        u8 *opt = (u8 *)rte_pktmbuf_prepend(m, 4);
        if (unlikely(opt == NULL))
        {
            free_mbuf(m);
            return false;
        }
        *(u16 *)opt = has_seq ? rte_cpu_to_be_16(info->gtpu_seq_num) : 0;
        opt[2] = has_npdu ? info->gtpu_npdu_num : 0;
        opt[3] = has_ext ? info->gtpu_next_ext_type : GTPU_EXT_NONE;
        gtpu_len += 4;
        if (has_seq)
            flags |= GTPU_FLAGS_SEQ;
        if (has_npdu)
            flags |= GTPU_FLAGS_NPDU;
    }

    gtpu_prepend_hdr(m, gtpu->outgoing_teid, gtpu_len, flags, msg_type);

    gtpu_prepend_udp_hdr(m, gtpu->transport.local.port, gtpu->transport.remote.port);

    return ipv4_send_mbuf_with_cache(&gtpu->transport.ip_tx_cache, m);
}

static void gtpu_send(transport_context_t *transport, u64 tsc)
{
#define GTPU_TX_BURST_SIZE 64
    struct rte_mbuf *mbufs[GTPU_TX_BURST_SIZE] = {0};

    fsocket_t *socket = transport_socket(transport);
    u32 n = fnp_ring_dequeue_burst(socket->tx, (void **)mbufs, (u32)GTPU_TX_BURST_SIZE);
    gtpu_context_t *gtpu = gtpu_context_cast(socket);
    for (u32 i = 0; i < n; ++i)
    {
        (void)gtpu_send_one(gtpu, mbufs[i]);
    }

    // 更新轮询时间戳
    if (likely(n > 0))
    {
        socket->polling_tsc = tsc;
    }
}

static bool gtpu_parse_ext_metadata(const u8 *ext, u16 ext_bytes, u8 ext_type, fmbuf_info_t *info)
{
    if (ext == NULL || info == NULL || ext_bytes < GTPU_EXT_HDR_UNIT)
    {
        return true;
    }

    switch (ext_type)
    {
    case GTPU_EXT_PDU_SESSION_CONTAINER:
        if (ext_bytes >= 3)
        {
            info->gtpu_qfi = ext[2] & 0x3fu;
            info->gtpu_rqi = (ext[2] >> 6) & 0x01u;
            info->gtpu_flags |= FNP_MBUF_GTPU_F_QFI | FNP_MBUF_GTPU_F_RQI;
        }
        break;
    case GTPU_EXT_NR_RAN_CONTAINER:
        if (ext_bytes >= 9)
        {
            u8 pdu_type = (ext[1] >> 4) & 0x0fu;
            if (pdu_type == 0 && ((ext[2] >> 3) & 0x01u))
            {
                info->gtpu_nr_pdcp_pdu_sn = ((u32)ext[6] << 16) | ((u32)ext[7] << 8) | ext[8];
                info->gtpu_flags |= FNP_MBUF_GTPU_F_NR_PDCP_SN;
            }
        }
        break;
    default:
        break;
    }

    return true;
}

static void gtpu_release(fsocket_t *socket)
{
    gtpu_context_t *gtpu = gtpu_context_cast(socket);

    fsocket_cleanup(socket);
    fnp_free(gtpu);
}

static void gtpu_release_when_idle(fsocket_t *socket)
{
    if (socket == NULL)
    {
        return;
    }

    if (fsocket_ref_count(socket) > 1)
    {
        if (fnp_master_retire_fsocket(socket, gtpu_release_when_idle) == FNP_OK)
        {
            return;
        }

        while (fsocket_ref_count(socket) > 1)
        {
            rte_pause();
        }
    }

    gtpu_release(socket);
}

static void gtpu_close(transport_context_t *transport)
{
    fsocket_t *socket = transport_socket(transport);
    gtpu_context_t *gtpu = gtpu_context_cast(socket);
    fsocket_enter_closing(socket);
    gtpu_unregister(gtpu);
    fsocket_mark_closed(socket);

    if (fnp_master_retire_fsocket(socket, gtpu_release_when_idle) == FNP_OK)
    {
        return;
    }

    (void)fnp_master_remove_fsocket(socket);
    gtpu_release_when_idle(socket);
}

u16 gtpu_socket_get_random_port()
{
    for (int i = 0; i < 10; ++i)
    {
        int port = random();
        // 判断端口没有使用
        return port;
    }

    return 0;
}

fsocket_t *gtpu_create_transport(void *conf, void *ctx)
{
    const fnp_gtpu_socket_conf_t *gtpu_conf = conf;
    const fnp_frontend_t *frontend = ctx;
    if (unlikely(gtpu_conf == NULL || gtpu_conf->remote.ip == 0 ||
                 gtpu_conf->incoming_teid == 0 || gtpu_conf->outgoing_teid == 0))
    {
        return NULL;
    }

    gtpu_context_t *gtpu = fnp_zmalloc(sizeof(*gtpu));
    if (unlikely(gtpu == NULL))
    {
        return NULL;
    }

    transport_context_t *transport = &gtpu->transport;
    fsocket_t *socket = transport_socket(transport);
    fsocket_init_base(socket, fsocket_type_gtpu);
    transport->ops = &gtpu_transport_ops;

    fsockaddr_copy(&transport->local, &gtpu_conf->local);
    fsockaddr_copy(&transport->remote, &gtpu_conf->remote);
    gtpu->incoming_teid = gtpu_conf->incoming_teid;
    gtpu->outgoing_teid = gtpu_conf->outgoing_teid;

    // 构造一个发送地址，端口不一样来使对端RSS分流，用于发送数据包给对端
    transport->send.family = FSOCKADDR_IPV4;
    transport->send.ip = transport->local.ip;
    u16 send_port = gtpu_socket_get_random_port();
    transport->send.port = fnp_swap16(send_port);

    // 初始化发送缓存用来加速发送路径，IP层会填充待确定字段
    ipv4_init_tx_cache(&transport->ip_tx_cache, IPPROTO_UDP,
                       &transport->send, &transport->remote);
    gtpu_format_name(gtpu);

    // 注册到全局表，才能被接收路径查到并分配到工作线程。
    if (gtpu_register(gtpu) != FNP_OK)
    {
        fnp_free(gtpu);
        return NULL;
    }

    // 尝试配对LDP，如果成功则直接走rx ring 和tx ring, 不需要经过fnp-deamon
    if (!gtpu_try_pair_ldp(gtpu))
    {
        // 没有配对成功，创建IO环路，走fnp-daemon
        if (fsocket_create_io_rings(socket, false) != FNP_OK)
        {
            gtpu_unregister(gtpu);
            fnp_free(gtpu);
            return NULL;
        }
    }

    printf("create socket %s\n", socket->name);
    return socket;
}

void gtpu_udp_input(struct rte_mbuf *m)
{
    if (unlikely(m->pkt_len < sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + GTPU_HDR_LEN))
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

    u16 gtpu_packet_bytes = udp_len - sizeof(struct rte_udp_hdr);
    gtpu_hdr_t *gtpu_hdr = rte_pktmbuf_mtod_offset(m, gtpu_hdr_t *, udp_offset + sizeof(struct rte_udp_hdr));
    if (unlikely((gtpu_hdr->flags & GTPU_FLAGS_V1_PT_MASK) != GTPU_FLAGS_V1_GPDU ||
                 (gtpu_hdr->msg_type != GTPU_MSGTYPE_GPDU && gtpu_hdr->msg_type != GTPU_MSGTYPE_END_MARKER)))
    {
        free_mbuf(m);
        return;
    }

    u16 gtpu_payload_len = rte_be_to_cpu_16(gtpu_hdr->msg_length);
    if (unlikely(gtpu_payload_len > gtpu_packet_bytes - GTPU_HDR_LEN))
    {
        free_mbuf(m);
        return;
    }

    u8 *gtpu_data = (u8 *)gtpu_hdr;
    u16 payload_offset = GTPU_HDR_LEN;
    u16 remaining = gtpu_payload_len;
    u8 next_ext_type = GTPU_EXT_NONE;
    bool has_optional_fields = (gtpu_hdr->flags & (GTPU_FLAGS_EXT | GTPU_FLAGS_SEQ | GTPU_FLAGS_NPDU)) != 0;
    if (has_optional_fields)
    {
        if (unlikely(remaining < 4))
        {
            free_mbuf(m);
            return;
        }
        next_ext_type = gtpu_data[payload_offset + 3];
        payload_offset += 4;
        remaining -= 4;
    }

    u32 incoming_teid = rte_be_to_cpu_32(gtpu_hdr->teid);
    gtpu_context_t *gtpu = gtpu_lookup_context(incoming_teid, ip_hdr->dst_addr, udp_hdr->dst_port);
    if (unlikely(gtpu == NULL))
    {
        free_mbuf(m);
        return;
    }
    fsocket_t *socket = transport_socket(&gtpu->transport);

    fmbuf_info_t *info = get_fmbuf_info(m);
    info->local.family = FSOCKADDR_IPV4;
    info->local.ip = ip_hdr->dst_addr;
    info->local.port = udp_hdr->dst_port;
    info->remote.family = FSOCKADDR_IPV4;
    info->remote.ip = ip_hdr->src_addr;
    info->remote.port = udp_hdr->src_port;
    info->gtpu_flags = FNP_MBUF_GTPU_F_MSG_TYPE;
    info->gtpu_msg_type = gtpu_hdr->msg_type;
    info->gtpu_next_ext_type = GTPU_EXT_NONE;
    info->gtpu_seq_num = 0;
    info->gtpu_npdu_num = 0;
    info->gtpu_qfi = 0;
    info->gtpu_rqi = 0;
    info->gtpu_ext_len = 0;
    info->gtpu_nr_pdcp_pdu_sn = 0;

    if ((gtpu_hdr->flags & GTPU_FLAGS_EXT) != 0)
    {
        while (next_ext_type != GTPU_EXT_NONE)
        {
            if (unlikely(remaining < 1))
            {
                free_mbuf(m);
                return;
            }

            u8 *ext = gtpu_data + payload_offset;
            u16 ext_bytes = (u16)ext[0] * GTPU_EXT_HDR_UNIT;
            if (unlikely(ext_bytes == 0 || ext_bytes > remaining))
            {
                free_mbuf(m);
                return;
            }

            gtpu_parse_ext_metadata(ext, ext_bytes, next_ext_type, info);
            next_ext_type = ext[ext_bytes - 1];
            payload_offset += ext_bytes;
            remaining -= ext_bytes;
        }
    }

    decap_len = udp_offset + sizeof(struct rte_udp_hdr) + payload_offset;
    rte_pktmbuf_adj(m, decap_len);
    int trim_len = (int)m->pkt_len - (int)remaining;
    if (trim_len > 0)
    {
        rte_pktmbuf_trim(m, trim_len);
    }

    gtpu_recv(&gtpu->transport, m);
}

int gtpu_module_init(void)
{
    int ret = gtpu_init_context();
    CHECK_RET(ret);

    return ipv4_register_input(IPPROTO_UDP, gtpu_udp_input);
}

int gtpu_export_socket_conf(const fsocket_t *socket, fnp_gtpu_socket_conf_t *conf)
{
    if (socket == NULL || conf == NULL || socket->type != fsocket_type_gtpu)
    {
        return FNP_ERR_PARAM;
    }

    const gtpu_context_t *gtpu = (const gtpu_context_t *)transport_const_from_socket(socket);
    fsockaddr_copy(&conf->local, &gtpu->transport.local);
    fsockaddr_copy(&conf->remote, &gtpu->transport.remote);
    conf->incoming_teid = gtpu->incoming_teid;
    conf->outgoing_teid = gtpu->outgoing_teid;
    return FNP_OK;
}
