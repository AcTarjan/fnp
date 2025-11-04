#ifndef FNP_SOCKADDR_H
#define FNP_SOCKADDR_H

#include "fnp_common.h"
#include "fnp_error.h"
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
    fnp_protocol_quic = 3, //暂时未使用的, 仅作为标识, 实际使用UDP
    fnp_protocol_tcp = IPPROTO_TCP,
    fnp_protocol_udp = IPPROTO_UDP,
} fnp_protocol_t;

static inline void fsockaddr_copy(fsockaddr_t* dst, const fsockaddr_t* src)
{
    if (unlikely(src == NULL))
    {
        dst->family = FSOCKADDR_NONE;
        dst->ip = 0;
        dst->port = 0;
        return;
    }
    dst->family = src->family;
    dst->ip = src->ip;
    dst->port = src->port;
}

static inline void fsockaddr2sockaddr_in(fsockaddr_t* faddr, sockaddr_in_t* addr)
{
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = faddr->ip;
    addr->sin_port = faddr->port;
}

static inline void sockaddr_in2fsockaddr(sockaddr_in_t* addr, fsockaddr_t* faddr)
{
    faddr->family = FSOCKADDR_IPV4;
    faddr->ip = addr->sin_addr.s_addr;
    faddr->port = addr->sin_port;
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
    addr->ip = fnp_ipv4_ston(ip);
    return FNP_OK;
}

#endif // FNP_SOCKADDR_H
