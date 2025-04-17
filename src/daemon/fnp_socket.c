#include "fnp_socket.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "tcp_sock.h"
#include "fnp_iface.h"

#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_vect.h>
#include <rte_errno.h>

#define SOCK_TABLE_SIZE 1024
#define RXTX_RING_SIZE 2048

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
static rte_xmm_t mask0 = {
    .u32 = {BIT_8_TO_15, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS}};

static inline xmm_t em_mask_key(void *key, xmm_t mask)
{
#if defined(__SSE2__)
    __m128i data = _mm_loadu_si128((__m128i *)(key));
    return _mm_and_si128(data, mask);
#elif defined(__ARM_NEON)
    int32x4_t data = vld1q_s32((int32_t *)key);
    return vandq_s32(data, mask);
#elif defined(RTE_ARCH_RISCV)
    xmm_t data = vect_load_128(key);
    return vect_and(data, mask);
#endif
}

static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
                                     uint32_t init_val)
{
    const fsockaddr_t *k;
    uint32_t t;
    const uint32_t *p;

    k = data;
    t = k->proto;
    p = (const uint32_t *)&k->rport;

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

static socket_handler socket_handlers[IPPROTO_UDP + 1];

int init_socket_layer()
{
    int socket_id = (int)rte_socket_id();
    char name[16];
    snprintf(name, sizeof(name), "socket_hash_%d", socket_id);
    struct rte_hash_parameters params = {
        .name = name,
        .entries = SOCK_TABLE_SIZE,
        .key_len = sizeof(fsockaddr_t),
        .hash_func = ipv4_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = socket_id,
    };

    /* create ipv4 hash */
    fnp.sockTbl = rte_hash_create(&params);
    if (fnp.sockTbl == NULL)
    {
        FNP_ERR("Unable to create the sock table on socket %d\n", socket_id);
        return -1;
    }

    socket_handlers[IPPROTO_TCP] = tcp_recv_from_app;
    socket_handlers[IPPROTO_UDP] = udp_recv_from_app;

    return 0;
}

static void encode_socket_name(fsocket_t *socket)
{
    char *ipstr1 = ipv4_ntos(socket->lip);
    u16 port1 = fnp_swap16(socket->lport);
    char *ipstr2 = ipv4_ntos(socket->rip);
    u16 port2 = fnp_swap16(socket->rport);

    if (socket->addr.proto == IPPROTO_UDP)
        sprintf(socket->name, "UDP%s:%d->%s:%d", ipstr1, port1, ipstr2, port2);
    else if (socket->addr.proto == IPPROTO_TCP)
        sprintf(socket->name, "TCP%s:%d->%s:%d", ipstr1, port1, ipstr2, port2);

    rte_free(ipstr1);
    rte_free(ipstr2);
}

int add_socket_to_hash(fsocket_t *socket)
{
    return rte_hash_add_key_data(fnp.sockTbl, &socket->addr, socket);
}

bool lookup_socket_from_hash(fsockaddr_t *addr)
{
    return rte_hash_lookup(fnp.sockTbl, addr) >= 0;
}

fsocket_t *get_socket_from_hash(struct rte_ipv4_hdr *hdr)
{
    fsocket_t *socket = NULL;
    fsockaddr_t key;

    void *data = (u8 *)hdr + offsetof(struct rte_ipv4_hdr, time_to_live);

    /*
     * Get 5 tuple: dst port, src port, dst IP address,
     * src IP address and protocol.
     */
    key.xmm = em_mask_key(data, mask0.x);

    // 查询连接是否存在
    if (rte_hash_lookup_data(fnp.sockTbl, (const void *)&key, &socket) >= 0)
    {
        return socket;
    }

    key.rip = 0;
    key.rport = 0;
    // 查询是否有监听的端口
    if (rte_hash_lookup_data(fnp.sockTbl, (const void *)&key, &socket) < 0)
    {
        return NULL;
    }

    return socket;
}

void remove_socket_from_hash(fsocket_t *socket)
{
    rte_hash_del_key(fnp.sockTbl, &socket->addr);
}

void show_all_socket()
{
    uint32_t next = 0;
    void *key = NULL;
    fsocket_t *socket = NULL;
    FNP_INFO("************sockets start***************\n");
    while (rte_hash_iterate(fnp.sockTbl, &key, (void **)&socket, &next) >= 0)
    {
        FNP_INFO("%s\n", socket->name);
    }
    FNP_INFO("************sockets end***************\n");
}

// 通过此接口最终释放socket
void free_socket(fsocket_t *socket)
{
    FNP_INFO("free socket: %s\n", socket->name)
    remove_socket_from_hash(socket);

    if (socket->rx != NULL)
        rte_ring_free(socket->rx);
    if (socket->tx != NULL)
        rte_ring_free(socket->tx);

    // 释放协议相关的资源
    if (socket->proto == IPPROTO_TCP)
    {
        free_tcp_sock((tcp_sock_t *)socket);
    }
    else if (socket->proto == IPPROTO_UDP)
    {
        free_udp_sock((udp_sock_t *)socket);
    }

    show_all_socket(); // 打印所有socket
}

// 初始化socket，交给用户程序使用
static int create_socket_ring(fsocket_t *socket)
{
    u32 socket_id = rte_socket_id();

    char ring_name[32] = {0};
    encode_ring_name(ring_name, "rx", socket);
    socket->rx = rte_ring_create(ring_name, RXTX_RING_SIZE, socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (socket->rx == NULL)
    {
        printf("Failed to create rx ring: %s\n", rte_strerror(rte_errno));
        return -1;
    }

    encode_ring_name(ring_name, "tx", socket);
    socket->tx = rte_ring_create(ring_name, RXTX_RING_SIZE, socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (socket->tx == NULL)
    {
        return -1;
    }

    // 生成socket的name
    encode_socket_name(socket);

    return 0;
}

fsocket_t *create_socket(fsockaddr_t *addr, i32 opt)
{
    fsocket_t *socket = NULL;

    // 检查本地ip是否合法
    fnp_iface_t *iface = lookup_iface(addr->lip);
    if (iface == NULL)
    {
        // FNP_ERR_IFACE_NOT_FOUND
        return NULL;
    }

    // 判断端口是否被占用
    if (lookup_socket_from_hash(addr))
    {
        // FNP_ERR_PORT_BINDED
        return NULL;
    }

    // 创建协议相关的sock
    switch (addr->proto)
    {
    case IPPROTO_UDP:
    {
        socket = (fsocket_t *)create_udp_sock();
        break;
    }
    case IPPROTO_TCP:
    {
        socket = (fsocket_t *)create_tcp_sock();
        break;
    }
    default:
    {
        FNP_INFO("unkown proto %d\n", addr->proto);
        return NULL;
    }
    }

    // 检查socket是否创建成功
    if (socket == NULL)
    {
        return NULL;
    }

    socket->iface = iface;
    copy_fnp_sockaddr(&socket->addr, addr);
    socket->opt = opt;
    socket->can_recv = true;  // 默认是能接收数据的
    socket->can_free = false; // 初始化完交给用户程序，不能释放了

    if (create_socket_ring(socket) != 0)
    {
        free_socket(socket);
        return NULL;
    }

    // 添加到hash表 TODO: 加锁
    if (add_socket_to_hash(socket) < 0)
    {
        FNP_WARN("add sock to hash failed\n");
        free_socket(socket);
        return NULL;
    }

    return socket;
}

// 提前确定下一跳mac地址
static int get_socket_next_mac(fsocket_t *socket, u32 rip)
{
    fnp_iface_t *iface = socket->iface;
    u32 next_ip = find_next_hop(iface, rip);

    struct rte_ether_addr *mac = arp_get_mac(next_ip);
    if (mac == NULL)
    {
        arp_send_request(iface, next_ip);
        return FNP_ERR_NO_ARP_CACHE;
    }

    rte_ether_addr_copy(mac, &socket->next_mac);
    return FNP_OK;
}

// 运行在控制线程
int socket_connect(fsocket_t *socket, u32 rip, u16 rport)
{
    int ret = get_socket_next_mac(socket, rip);
    CHECK_RET(ret);

    // 从hash表删除原先的socket
    remove_socket_from_hash(socket);

    socket->addr.rip = rip;
    socket->addr.rport = rport;

    // 添加到hash表
    if (add_socket_to_hash(socket) < 0)
    {
        free_socket(socket);
        return FNP_ERR_ADD_HASH;
    }

    switch (socket->proto)
    {
    case IPPROTO_TCP:
    {
        // 通知协议栈进行连接
        set_socket_req(socket, FNP_CONNECT_REQ);
        break;
    }
    case IPPROTO_UDP:
    {
        udp_sock_t *sock = socket;
        sock->send_func = udp_fast_send_mbuf;
        break;
    }
    }

    return 0;
}

void recv_data_from_app()
{
    uint32_t next = 0;
    void *key = NULL;
    fsocket_t *socket = NULL;
    while (rte_hash_iterate(fnp.sockTbl, &key, (void **)&socket, &next) >= 0)
    {
        // UDP 或 TCP的处理函数
        socket_handlers[socket->proto](socket);
        // socket->handler(socket);
    }
}
