#ifndef FNP_COMMON_H
#define FNP_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;
typedef char i8;
typedef short i16;
typedef int i32;
typedef long long int i64;

#define USE_DPDK

#ifdef USE_DPDK
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
    #define fnp_malloc(size)                rte_malloc("", (size), 0)
    #define fnp_zmalloc(size)               rte_zmalloc("", (size), 0)
    #define fnp_memcpy(dst, src, len)       rte_memcpy((dst), (src), (len))
    #define fnp_free(obj)                   rte_free((obj))
    #define fnp_swap_32(x)                  rte_cpu_to_be_32((x))
    #define fnp_swap_16(x)                  rte_cpu_to_be_16((x))

#define FNP_DEBUG(fmt, args...) \
    RTE_LOG(DEBUG, USER1, fmt, ##args);
#define FNP_INFO(fmt, args...) \
    RTE_LOG(INFO, USER1, fmt, ##args);
#define FNP_WARN(fmt, args...) \
    RTE_LOG(WARNING, USER1, fmt, ##args);
#define FNP_ERR(fmt, args...) \
    RTE_LOG(ERR, USER1, fmt, ##args);
#else
    #define fnp_malloc(size)                malloc((size))
    #define fnp_zmalloc(size)               calloc((size),1)
    #define fnp_memcpy(dst, src, len)       memcpy((dst), (src), (len))
    #define fnp_free(obj)                   free((obj))
    #define fnp_swap_32(x)                  htonl((x))
    #define fnp_swap_16(x)                  htons((x))
#endif

#define FNP_MIN(a, b) \
__extension__ ({ \
typeof (a) _a = (a); \
typeof (b) _b = (b); \
_a < _b ? _a : _b; \
})

#define FNP_MAX(a, b) \
__extension__ ({ \
typeof (a) _a = (a); \
typeof (b) _b = (b); \
_a > _b ? _a : _b; \
})

//#define likely(a) __glibc_likely((a))

static inline uint32_t ipv4_ston(const char* ip)
{
    if (ip == NULL)
        return 0;
    struct in_addr addr;
    inet_aton(ip, &addr);

    return addr.s_addr;
}

static inline char* ipv4_ntos(uint32_t ip)
{
    u8 seg1 = ip & 0xFF;
    u8 seg2 = (ip >> 8) & 0xFF;
    u8 seg3 = (ip >> 16) & 0xFF;
    u8 seg4 = (ip >> 24) & 0xFF;
    char* str = rte_malloc(NULL,16, 0);
    sprintf(str, "%d.%d.%d.%d", seg1, seg2, seg3, seg4);
    return str;
}

#define FNP_MBUF_MEMPOOL_NAME   "fnp_mbuf_pool"

typedef struct sockinfo
{
    uint32_t lip;
    uint32_t rip;
    uint16_t lport;
    uint16_t rport;
    uint8_t proto;
} sockinfo_t;

#define sockinfo(m) (m)->buf_addr

#endif //FNP_COMMON_H
