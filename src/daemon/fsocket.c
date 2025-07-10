#include "fnp_socket.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "udp.h"
#include "quic.h"
#include "tcp_sock.h"

#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_vect.h>
#include <rte_errno.h>

#include "fnp_worker.h"
#include "fnp_iface.h"
#include "flow_table.h"

#define SOCK_TABLE_SIZE 1024
#define RXTX_RING_SIZE 2048

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00

typedef union socket_key
{
    struct
    {
        u8 pad0;
        u8 proto;
        u16 pad1;
        u32 rip;
        u32 lip;
        u16 rport;
        u16 lport;
    };

    xmm_t xmm;
} socket_key_t;


static inline void init_socket_key(socket_key_t* key, fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote)
{
    key->pad0 = 0;
    key->pad1 = 0;
    key->proto = proto;
    key->lip = local ? local->ip : 0;
    key->rip = remote ? remote->ip : 0;
    key->lport = local ? local->port : 0;
    key->rport = remote ? remote->port : 0;
}

static rte_xmm_t mask0 = {.u32 = {BIT_8_TO_15, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS}};

static inline xmm_t em_mask_key(void* key, xmm_t mask)
{
#if defined(__SSE2__)
    __m128i data = _mm_loadu_si128((__m128i*)(key));
    return _mm_and_si128(data, mask);
#elif defined(__ARM_NEON)
    int32x4_t data = vld1q_s32((int32_t *)key);
    return vandq_s32(data, mask);
#elif defined(RTE_ARCH_RISCV)
    xmm_t data = vect_load_128(key);
    return vect_and(data, mask);
#endif
}

static inline uint32_t ipv4_hash_crc(const void* data, __rte_unused uint32_t data_len,
                                     uint32_t init_val)
{
    const socket_key_t* k;
    uint32_t t;
    const uint32_t* p;

    k = data;
    t = k->proto;
    p = (const uint32_t*)&k->rport;

#ifdef EM_HASH_CRC
    init_val = rte_hash_crc_4byte(t, init_val);
    init_val = rte_hash_crc_4byte(k->ip_src, init_val);
    init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
    init_val = rte_hash_crc_4byte(*p, init_val);
#else
    init_val = rte_jhash_1word(t, init_val);
    init_val = rte_jhash_1word(k->rip, init_val);
    init_val = rte_jhash_1word(k->lip, init_val);
    init_val = rte_jhash_1word(*p, init_val);
#endif

    return init_val;
}


struct rte_hash* create_socket_table()
{
    int socket_id = (int)rte_socket_id();
    char name[32];
    sprintf(name, "fnp_socket_table");
    struct rte_hash_parameters params = {
        .name = name,
        .entries = SOCK_TABLE_SIZE,
        .key_len = sizeof(socket_key_t),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = socket_id,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY, //无锁模式, 多读少写的场景, 删除操作不会立即释放位置
        // | RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL // 禁止删除时自动释放内存,
    };

    /* create ipv4 hash */
    return rte_hash_create(&params);
}

int add_socket_to_table(fsocket_t* socket)
{
    socket_key_t key;
    init_socket_key(&key, socket->proto, &socket->local, &socket->remote);
    return rte_hash_add_key_data(fnp.sockTbl, &key, socket);
}

int delete_socket_from_table(fsocket_t* socket)
{
    socket_key_t key;
    init_socket_key(&key, socket->proto, &socket->local, &socket->remote);
    return rte_hash_del_key(fnp.sockTbl, &key) >= 0;
}

fsocket_t* lookup_socket_table(fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote)
{
    socket_key_t key;
    init_socket_key(&key, proto, local, remote);
    fsocket_t* socket = NULL;
    rte_hash_lookup_data(fnp.sockTbl, &key, (void**)&socket);
    return socket;
}

fsocket_t* lookup_socket_table_by_ipv4(struct rte_ipv4_hdr* hdr)
{
    fsocket_t* socket = NULL;
    socket_key_t key;

    void* data = (u8*)hdr + offsetof(struct rte_ipv4_hdr, time_to_live);

    /*
     * Get 5 tuple: dst port, src port, dst IP address,
     * src IP address and protocol.
     */
    key.xmm = em_mask_key(data, mask0.x);

    // 查询本地socket是否存在
    if (rte_hash_lookup_data(fnp.sockTbl, (const void*)&key, &socket) >= 0)
    {
        return socket;
    }

    key.rip = 0;
    key.rport = 0;
    if (rte_hash_lookup_data(fnp.sockTbl, (const void*)&key, &socket) < 0)
    {
        return NULL;
    }

    return socket;
}


static void encode_socket_name(fsocket_t* socket)
{
    char* local_ip = ipv4_ntos(socket->local.ip);
    char* remote_ip = ipv4_ntos(socket->remote.ip);
    u16 local_port = fnp_swap16(socket->local.port);
    u16 remote_port = fnp_swap16(socket->remote.port);

    if (socket->proto == fnp_protocol_udp)
        sprintf(socket->name, "UDP-%s:%d->%s:%d", local_ip, local_port, remote_ip, remote_port);
    else if (socket->proto == fnp_protocol_tcp)
        sprintf(socket->name, "TCP-%s:%d->%s:%d", local_ip, local_port, remote_ip, remote_port);
    else if (socket->proto == fnp_protocol_quic)
        sprintf(socket->name, "QUIC-%s:%d->%s:%d", local_ip, local_port, remote_ip, remote_port);

    fnp_string_free(local_ip);
    fnp_string_free(remote_ip);
}

void show_all_socket()
{
    uint32_t next = 0;
    socket_key_t key;
    fsocket_t* socket = NULL;
    FNP_INFO("************sockets start***************\n");
    while (rte_hash_iterate(fnp.sockTbl, (void*)&key, (void**)&socket, &next) >= 0)
    {
        printf("socket: %s", socket->name);
    }
    FNP_INFO("************sockets end***************\n");
}


// 初始化socket，交给用户程序使用
int fnp_socket_init(fsocket_t* socket, fnp_protocol_t proto,
                    fsockaddr_t* local, fsockaddr_t* remote)
{
    socket->proto = proto;
    fsockaddr_copy(&socket->local, local);
    fsockaddr_copy(&socket->remote, remote);

    encode_socket_name(socket);

    printf("create socket: %s\n", socket->name);

    // remote也是本地的, 直接本地通信
    if (is_udp_socket(socket) && remote != NULL && lookup_iface(remote->ip) != NULL)
    {
        socket->is_local_communication = 1;
        // 查找对方的socket
        fsocket_t* rsocket = lookup_socket_table(socket->proto, &socket->remote, &socket->local);
        if (rsocket != NULL)
        {
            socket->rx = fnp_pring_clone(rsocket->tx);
            socket->tx = fnp_pring_clone(rsocket->rx);
            return FNP_OK;
        }

        // 对方是一个udp server socket
        rsocket = lookup_socket_table(socket->proto, &socket->remote, NULL);
        if (rsocket != NULL)
        {
            socket->tx = fnp_pring_clone(rsocket->rx); //直接写入到对方的接收缓存
            socket->rx = fnp_pring_create(256, false, false); //本地的接收缓存需要重新创建
            if (socket->rx == NULL)
            {
                printf("Failed to create rx ring\n");
                return FNP_ERR_CREATE_RING;
            }
            return FNP_OK;
        }
    }

    // 对于server socket, 必须支持多生产者
    socket->rx = fnp_pring_create(1024, remote == NULL, false);
    if (socket->rx == NULL)
    {
        printf("Failed to create rx ring\n");
        return FNP_ERR_CREATE_RING;
    }

    socket->tx = fnp_pring_create(1024, false, false);
    if (socket->tx == NULL)
    {
        printf("Failed to create rx ring\n");
        return FNP_ERR_CREATE_RING;
    }

    return FNP_OK;
}

fsocket_t* create_fsocket(fnp_protocol_t proto, fsockaddr_t* local, fsockaddr_t* remote, void* conf, int worker_id)
{
    // 检查本地ip是否合法
    fnp_iface_t* iface = lookup_iface(local->ip);
    if (iface == NULL)
    {
        printf("can't find iface for %d\n", local->ip);
        return NULL;
    }

    // 判断socket是否已经存在
    fsocket_t* old_socket = lookup_socket_table(proto, local, remote);
    if (old_socket != NULL)
    {
        printf("socket exists\n");
        return NULL;
    }

    fsocket_t* socket = NULL;
    // 创建协议相关的sock
    if (proto == fnp_protocol_udp)
    {
        socket = (fsocket_t*)udp_create_sock(local, remote);
    }
    else if (proto == fnp_protocol_tcp)
    {
        socket = (fsocket_t*)tcp_create_sock(local, remote, conf);
    }
    else if (proto == fnp_protocol_quic)
    {
        socket = (fsocket_t*)quic_create_context(local, conf);
    }

    // 检查socket是否创建成功
    if (socket == NULL)
    {
        return NULL;
    }

    if (fnp_socket_init(socket, proto, local, remote) != FNP_OK)
    {
        free_fsocket(socket);
        return NULL;
    }

    // 添加socket到master socket表
    if (add_socket_to_table(socket) != FNP_OK)
    {
        free_fsocket(socket);
        return NULL;
    }


    dispatch_socket_to_worker(socket, worker_id);

    // show_all_socket();  // 打印所有socket

    return socket;
}


// 通过此接口最终释放socket
void free_fsocket(fsocket_t* socket)
{
    FNP_INFO("start to free socket %s\n", socket->name);

    // 从哈希表中删除
    if (!delete_socket_from_table(socket))
    {
        FNP_ERR("fail to delete socket from table\n");
    }

    remove_socket_from_worker(socket);

    fnp_pring_free(socket->rx);
    fnp_pring_free(socket->tx);

    // delete_flow_rule();

    // 释放协议相关的资源
    if (socket->proto == fnp_protocol_tcp)
    {
        free_tcp_sock((tcp_sock_t*)socket);
    }
    else if (socket->proto == fnp_protocol_udp)
    {
        free_udp_sock((udp_sock_t*)socket);
    }
    else if (socket->proto == fnp_protocol_quic)
    {
        quic_free_context((quic_context_t*)socket);
    }

    show_all_socket(); // 打印所有socket
}

