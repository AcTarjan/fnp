#ifndef FNP_SOCKADDR_H
#define FNP_SOCKADDR_H

#include "fnp_common.h"
#include "fnp_error.h"
#include <arpa/inet.h>
#include <netinet/in.h>

typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr_in6 sockaddr_in6_t;

#define FNP_SO_REUSEADDR 0x01
#define FNP_SO_REUSEPORT 0x02

#define FSOCKADDR_NONE   0
#define FSOCKADDR_IPV4   4
#define FSOCKADDR_IPV6   6

typedef struct fsockaddr
{
    u16 family;
    u16 port;
    u32 ip;
} fsockaddr_t;

typedef enum fnp_protocol
{
    fnp_protocol_tcp = IPPROTO_TCP,
    fnp_protocol_udp = IPPROTO_UDP,
    fnp_protocol_quic = 3, //暂时未使用的, 仅作为标识, 实际使用UDP
} fnp_protocol_t;


static inline void fsockaddr_copy(fsockaddr_t* dst, const fsockaddr_t* src)
{
    if (src == NULL)
    {
        dst->family = FSOCKADDR_NONE;
        return;
    }
    dst->family = src->family;
    dst->ip = src->ip;
    dst->port = src->port;
}

static inline bool fsockaddr_compare(const fsockaddr_t* expected, const fsockaddr_t* actual)
{
    if (expected == NULL || actual == NULL)
        return false;
    if (expected->family == actual->family && expected->family == FSOCKADDR_IPV4)
    {
        return expected->ip == actual->ip &&
            expected->port == actual->port;
    }

    return false;
}

static inline int fsockaddr_init(fsockaddr_t* addr, int family, const char* ip, int port)
{
    if (addr == NULL)
        return -1;

    addr->family = family;
    addr->port = fnp_swap16(port);
    addr->ip = ipv4_ston(ip);
    return FNP_OK;
}

// 最大256字节
// 参见picoquic_stateless_packet_t
typedef struct fnp_mbuf_info
{
    fsockaddr_t local;
    fsockaddr_t remote;
} fmbuf_info_t;

#define get_fmbuf_info(m) (fmbuf_info_t *)rte_mbuf_to_priv(m);

#endif // FNP_SOCKADDR_H
