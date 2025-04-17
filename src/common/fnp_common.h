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

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>

#define fnp_malloc(size) rte_malloc(NULL, (size), 0)
#define fnp_zmalloc(size) rte_zmalloc(NULL, (size), 0)
#define fnp_memcpy(dst, src, len) rte_memcpy((dst), (src), (len))
#define fnp_free(obj) rte_free((obj))
#define fnp_swap32(x) rte_cpu_to_be_32((x))
#define fnp_swap16(x) rte_cpu_to_be_16((x))

char* fnp_string_duplicate(const char* original);

void fnp_string_free(char* str);

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
    struct in_addr addr;
    addr.s_addr = ip;
    char* str = inet_ntoa(addr);
    return fnp_string_duplicate(str);
}

#define FNP_INFO(fmt, args...) \
    RTE_LOG(INFO, USER1, fmt, ##args);
#define FNP_WARN(fmt, args...) \
    RTE_LOG(WARNING, USER1, fmt, ##args);
#define FNP_ERR(fmt, args...) \
    RTE_LOG(ERR, USER1, fmt, ##args);

#define FNP_MIN(a, b)       \
    __extension__({         \
        typeof(a) _a = (a); \
        typeof(b) _b = (b); \
        _a < _b ? _a : _b;  \
    })

#define FNP_MAX(a, b)       \
    __extension__({         \
        typeof(a) _a = (a); \
        typeof(b) _b = (b); \
        _a > _b ? _a : _b;  \
    })

// #define likely(a) __glibc_likely((a))

#define FNP_MBUF_MEMPOOL_NAME "fnp_mbuf_pool"


#endif // FNP_COMMON_H
