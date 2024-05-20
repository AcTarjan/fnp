#ifndef FNP_COMMON_H
#define FNP_COMMON_H

#include <stdlib.h>
#include <string.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <arpa/inet.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;
typedef char i8;
typedef short i16;
typedef int i32;
typedef long long int i64;

#ifdef USE_DPDK
    #define fnp_malloc(size)                rte_malloc("", (size), 0)
    #define fnp_zmalloc(size)               rte_zmalloc("", (size), 0)
    #define fnp_memcpy(dst, src, len)       rte_memcpy((dst), (src), (len))
    #define fnp_free(obj)                   rte_free((obj))
    #define fnp_swap_32(x)                  rte_cpu_to_be_32((x))
    #define fnp_swap_16(x)                  rte_cpu_to_be_16((x))
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

static inline void fnp_print_ipv4(u32 ip)
{
    u8 seg1 = ip & 0xff;
    u8 seg2 = (ip >> 8) & 0xff;
    u8 seg3 = (ip >> 16) & 0xff;
    u8 seg4 = (ip >> 24) & 0xff;
    printf("%u.%u.%u.%u\n",seg1,seg2,seg3,seg4);
}

static inline u32 fnp_ipv4_ston(char* ip_str)
{
    struct in_addr addr;
    inet_aton(ip_str, &addr);

    return addr.s_addr;
}

#endif //FNP_COMMON_H
