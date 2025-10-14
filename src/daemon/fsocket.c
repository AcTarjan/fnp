#include "fsocket.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "udp.h"
#include "quic.h"
#include "tcp.h"

#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_vect.h>
#include <rte_errno.h>

#include "fnp_worker.h"
#include "fnp_iface.h"

#define SOCK_TABLE_SIZE 1024000
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
    int32x4_t data = vld1q_s32((int32_t*)key);
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
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
        //无锁模式, 多读少写的场景, 删除操作不会立即释放位置
        // | RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL // 禁止删除时自动释放内存,
        //  RTE_HASH_EXTRA_FLAGS_EXT_TABLE
    };

    /* create ipv4 hash */
    return rte_hash_create(&params);
}

int add_fsocket_to_table(fsocket_t* socket)
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


static inline void encode_fsocket_name(fsocket_t* socket)
{
    char* local_ip = fnp_ipv4_ntos(socket->local.ip);
    char* remote_ip = fnp_ipv4_ntos(socket->remote.ip);
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

static inline int create_fsocket_ring(fsocket_t* socket)
{
    // 对于server socket, 必须支持多生产者
    bool is_mp = (socket->remote.ip == 0);
    socket->rx = fnp_ring_create(256, is_mp, false);
    if (socket->rx == NULL)
    {
        printf("Failed to create rx ring\n");
        return FNP_ERR_CREATE_RING;
    }

    // 创建eventfd
    socket->rx_efd_in_backend = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (socket->rx_efd_in_backend < 0)
    {
        return FNP_ERR_CREATE_EVENTFD;
    }

    if (is_tcp_server_socket(socket))
    {
        return FNP_OK;
    }

    socket->tx = fnp_ring_create(256, false, false);
    if (socket->tx == NULL)
    {
        printf("Failed to create tx ring\n");
        return FNP_ERR_CREATE_RING;
    }

    socket->tx_efd_in_backend = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (socket->tx_efd_in_backend < 0)
    {
        return FNP_ERR_CREATE_EVENTFD;
    }

    socket->net_rx = fnp_ring_create(256, false, false);
    if (socket->net_rx == NULL)
    {
        printf("Failed to create net_rx ring\n");
        return FNP_ERR_CREATE_RING;
    }

    // 会被前端重新修正
    socket->rx_efd_in_frontend = socket->rx_efd_in_backend;
    socket->tx_efd_in_frontend = socket->tx_efd_in_backend;

    return FNP_OK;
}

// 构建本地直接路径：互为目的Socket的两个Socket可以通过交换ring和eventfd直接通信
// UDP: 目的地址确定，
// TCP: 目的地址正在被监听
// QUIC: 不支持
int build_local_direct_path(fsocket_t* socket)
{
    // 查看对端的socket是否存在
    fsocket_t* peer_socket = lookup_socket_table(socket->proto, &socket->remote, &socket->local);
    if (peer_socket != NULL)
    {
        // 交换ring和eventfd
        socket->rx = fnp_ring_clone(peer_socket->tx);
        socket->tx = fnp_ring_clone(peer_socket->rx);
        socket->rx_efd_in_backend = peer_socket->tx_efd_in_backend;
        socket->tx_efd_in_backend = peer_socket->rx_efd_in_backend;
        // 会被前端重新修正
        socket->rx_efd_in_frontend = socket->rx_efd_in_backend;
        socket->tx_efd_in_frontend = socket->tx_efd_in_backend;
        socket->is_ldp = true;

        //对于UDP来说，Socket已经被worker监听
        return FNP_OK;
    }

    // 对端socket不存在，创建ring和eventfd
    if (create_fsocket_ring(socket) != FNP_OK)
    {
        return FNP_ERR_GENERIC;
    }

    if (socket->proto == fnp_protocol_tcp)
    {
        // 查看是否监听目的端口
        fsocket_t* server_socket = lookup_socket_table(fnp_protocol_tcp, &socket->remote, NULL);
        if (server_socket == NULL)
        {
            // 端口没有监听，connect会失败
            return FNP_ERR_GENERIC;
        }

        // 跳过3次握手,直接进入ESTABLISHED状态, 创建对端socket
        peer_socket = create_fsocket(socket->proto, &socket->remote, &socket->local, NULL, server_socket->worker_id);
        if (peer_socket == NULL)
        {
            return FNP_ERR_GENERIC;
        }

        // server socket接受到新连接，入队列
        fnp_ring_enqueue(server_socket->rx, peer_socket);
        fsocket_notify_frontend(server_socket);

        socket->is_ldp = true;
        return FNP_OK;
    }

    return FNP_OK;
}

// 初始化socket，交给用户程序使用
static inline int init_fsocket(fsocket_t* socket, fnp_protocol_t proto,
                               fsockaddr_t* local, fsockaddr_t* remote)
{
    socket->proto = proto;
    fsockaddr_copy(&socket->local, local);
    fsockaddr_copy(&socket->remote, remote);

    encode_fsocket_name(socket);

    // 5元组必须全部确定，且目的IP为本地IP
    if (socket->local.ip != 0 && is_local_ipaddr(socket->remote.ip))
    {
        return build_local_direct_path(socket);
    }

    return create_fsocket_ring(socket);
}

static inline int fnp_epoll_add_fsocket(int epoll_fd, fsocket_t* socket)
{
    int fd = socket->tx_efd_in_backend;
    struct epoll_event ev = {0}; // 注意，必须初始化为0，否则read value会有异常
    ev.events = EPOLLIN | EPOLLET; // 边沿触发，正常是指0到非0值才会触发，与epoll配合后，值变化就会触发
    ev.data.ptr = (void*)socket;
    // 注意ev.data是一个union，ptr,fd,u32和u64只能设置一个值。

    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
}

static inline void dispatch_fsocket_to_worker(fsocket_t* socket, int worker_id)
{
    // tcp server socket和本地通信socket不需要分配到worker
    if (is_tcp_server_socket(socket) || socket->is_ldp)
    {
        socket->worker_id = FNP_MAX_WORKER_NUM;
        return;
    }

    // master创建的socket
    if (worker_id < 0)
    {
        // TODO: 负载均衡
        worker_id = 0;
    }

    socket->worker_id = worker_id;
    // 添加socket到worker的epoll中
    fnp_worker_t* worker = get_fnp_worker(worker_id);
    fnp_epoll_add_fsocket(worker->epoll_fd, socket);
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
        printf("socket malloc fail!\n");
        return NULL;
    }

    if (init_fsocket(socket, proto, local, remote) != FNP_OK)
    {
        printf("socket init fail\n");
        free_fsocket(socket);
        return NULL;
    }

    // 添加socket到master socket表
    if (add_fsocket_to_table(socket) != FNP_OK)
    {
        printf("fail to add socket to table\n");
        free_fsocket(socket);
        return NULL;
    }

    //分配socket给worker来处理
    dispatch_fsocket_to_worker(socket, worker_id);

    return socket;
}

static inline void remove_socket_from_worker(fsocket_t* socket)
{
    if (socket->worker_id == FNP_MAX_WORKER_NUM)
    {
        // tcp server socket 和 local udp socket不需要从worker中删除
        return;
    }

    fnp_worker_t* worker = get_fnp_worker(socket->worker_id);
    epoll_ctl(worker->epoll_fd, EPOLL_CTL_DEL, socket->tx_efd_in_backend, NULL);
}

// 通过此接口最终释放socket
void free_fsocket(fsocket_t* socket)
{
    // FNP_INFO("start to free socket %s\n", socket->name);

    // 从哈希表中删除, 可能插入失败
    delete_socket_from_table(socket);

    remove_socket_from_worker(socket);

    struct rte_mbuf* m = NULL;
    if (likely(socket->rx != NULL))
    {
        while (fnp_ring_dequeue(socket->rx, (void**)&m))
            free_mbuf(m);
        fnp_ring_free(socket->rx);
    }
    if (likely(socket->tx != NULL))
    {
        while (fnp_ring_dequeue(socket->tx, (void**)&m))
            free_mbuf(m);
        fnp_ring_free(socket->tx);
    }
    if (likely(socket->net_rx != NULL))
    {
        while (fnp_ring_dequeue(socket->net_rx, (void**)&m))
            free_mbuf(m);
        fnp_ring_free(socket->net_rx);
    }

    // 关闭eventfd
    if (socket->rx_efd_in_backend >= 0)
        close(socket->rx_efd_in_backend);
    if (socket->tx_efd_in_backend >= 0)
        close(socket->tx_efd_in_backend);

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

    // show_all_socket(); // 打印所有socket
}

void close_fsocket(fsocket_t* socket)
{
    // udp socket或者未分配worker的socket直接释放
    if (socket->proto == fnp_protocol_udp || socket->worker_id == FNP_MAX_WORKER_NUM)
    {
        // 直接释放
        free_fsocket(socket);
    }
    else if (socket->proto == fnp_protocol_tcp)
    {
        // 通知worker执行4次挥手
        fnp_msg_t* msg = fmsg_new(fmsg_type_close_fsocket);
        msg->ptr = socket;
        fnp_worker_t* worker = get_fnp_worker(socket->worker_id);
        if (unlikely(fnp_ring_enqueue(worker->fmsg_ring, msg) == 0))
        {
            // 通知失败，直接释放
            fnp_free(msg);
            free_fsocket(socket);
        }
    }
}

void show_all_fsocket()
{
    i32 count = rte_hash_count(fnp.sockTbl);
    FNP_INFO("socket count is %d\n", count);
    uint32_t next = 0;
    socket_key_t key;
    fsocket_t* socket = NULL;
    FNP_INFO("************sockets start***************\n");
    while (rte_hash_iterate(fnp.sockTbl, (void*)&key, (void**)&socket, &next) >= 0)
    {
        FNP_INFO("socket: %s\n", socket->name);
    }
    FNP_INFO("************sockets end***************\n");
}
