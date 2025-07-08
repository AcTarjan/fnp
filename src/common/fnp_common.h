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


// 获取CPU时钟周期数
static inline u64 fnp_get_tsc()
{
    return rte_rdtsc();
}

// 获取精确的CPU时钟周期数
static inline u64 fnp_get_precise_tsc()
{
    return rte_rdtsc_precise();
}

// 获取CPU时钟频率
static inline u64 fnp_get_tsc_hz()
{
    return rte_get_tsc_hz();
}

// 释放CPU
static inline void fnp_sleep(u64 us)
{
    rte_delay_us_sleep(us);
}

// 阻塞CPU
static inline void fnp_block(u64 us)
{
    rte_delay_us_block(us);
}

// 将线程在DPDK的指定lcore上运行
typedef int (fnp_lcore_function_t)(void*);

static inline int fnp_launch_on_lcore(fnp_lcore_function_t* f, void* arg, int lcore_id)
{
    if (lcore_id == -1)
    {
        lcore_id = rte_get_next_lcore(0, 1, 0);
    }
    return rte_eal_remote_launch(f, arg, lcore_id);
}


#endif // FNP_COMMON_H
