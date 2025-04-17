#ifndef FNP_SOCKET_H
#define FNP_SOCKET_H

#include "fnp_sockaddr.h"
#include "fnp_iface.h"
#include "fnp_error.h"

#include <rte_ip.h>

#define FNP_SO_REUSEADDR 0x01
#define FNP_SO_REUSEPORT 0x02

#define FNP_CONNECT_REQ 0x01
#define FNP_CLOSE_REQ 0x02

#define SOCKET_TX_BURST_NUM 16

typedef struct fnp_socket fsocket_t;

typedef void (*socket_handler)(fsocket_t *);

typedef struct fnp_socket
{
    union
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
        fsockaddr_t addr;
    };
    socket_handler handler; // 负责socket协议处理的函数
    struct rte_ring *rx;    // 从fnp-daemon接收数据的队列
    struct rte_ring *tx;    // 向fnp-daemon发送数据的队列
    i32 opt;                // socket的可选标记
    i32 user_req;           // user向fnp-daemon发送的用户请求，仅用户修改, 不能直接修改tcp state，因为多线程冲突
    fnp_iface_t *iface;
    struct rte_ether_addr next_mac;
    bool can_recv; // 是否还可以接收数据，主要用于TCP
    bool can_free; // daemon处是否可以释放, 被用户使用就不能释放.
    char name[64]; // name of socket
} fsocket_t;

#define fsocket(sock) ((fsocket_t *)sock)

int init_socket_layer();

// 协议栈内部使用，使用情况
// 1. 收到TCP连接请求时调用
// 2. picoquic创建udp
fsocket_t *create_socket(fsockaddr_t *addr, i32 opt);

int socket_connect(fsocket_t *socket, u32 rip, u16 rport);

static inline void set_socket_opt(fsocket_t *socket, i32 opt)
{
    socket->opt |= opt;
}

static inline bool get_socket_opt(fsocket_t *socket, i32 opt)
{
    return socket->opt & opt;
}

static inline void set_socket_req(fsocket_t *socket, i32 req)
{
    socket->user_req = req;
}

int add_socket_to_hash(fsocket_t *socket);

bool lookup_socket_from_hash(fsockaddr_t *addr);

// 接收数据包时，根据数据包的5元组信息查找对应的sock
fsocket_t *get_socket_from_hash(struct rte_ipv4_hdr *hdr);

void remove_socket_from_hash(fsocket_t *socket);

void free_socket(fsocket_t *socket);

// 处理应用层数据, 然后发送出去
void recv_data_from_app();

#endif // FNP_SOCKET_H
