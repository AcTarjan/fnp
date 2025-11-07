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
#define fnp_memcpy(dst, src, len) memcpy((dst), (src), (len))
#define fnp_free(obj) rte_free((obj))
#define fnp_swap32(x) rte_cpu_to_be_32((x))
#define fnp_swap16(x) rte_cpu_to_be_16((x))

#define FNP_MBUFPOOL_PRIV_SIZE 128

#define FNP_MAX_WORKER_NUM 4

static inline char* fnp_string_duplicate(const char* original)
{
    if (original == NULL)
    {
        return NULL;
    }
    size_t len = strlen(original);

    int allocated = len + 1;
    char* str = (char*)fnp_malloc(allocated);
    if (str != NULL)
    {
        fnp_memcpy(str, original, len);
        str[allocated - 1] = 0;
    }

    return str;
}

static inline void fnp_string_free(char* str)
{
    if (str != NULL)
    {
        fnp_free(str);
    }
}

static inline u32 fnp_ipv4_ston(const char* ip)
{
    if (ip == NULL)
        return 0;
    struct in_addr addr;
    inet_aton(ip, &addr);

    return addr.s_addr;
}

static inline char* fnp_ipv4_ntos(uint32_t ip)
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
        // 自动选择一个空闲的 lcore
        for (lcore_id = rte_get_next_lcore(-1, 1, 0);
             lcore_id < RTE_MAX_LCORE;
             lcore_id = rte_get_next_lcore(lcore_id, 1, 0))
        {
            // 只在 main lcore 上调用：查看该 lcore 当前状态
            if (rte_eal_get_lcore_state(lcore_id) == WAIT)
            {
                break; // 这个 lcore 已启用且尚未被 launch
            }
        }
        if (lcore_id == RTE_MAX_LCORE)
        {
            return -1; // 没有可用的 lcore
        }
    }
    return rte_eal_remote_launch(f, arg, lcore_id);
}

// 测试速率
typedef struct fnp_rate_measure
{
    FILE* file; // 文件指针，用于记录速率测量结果
    u64 interval_count; // 间隔计数
    u64 packet_count; //数据包计数
    u64 byte_count; //字节计数
    u64 first_tsc; // 第一个数据包的时间戳
    u64 last_tsc; // 最后一个数据包的时间戳
} fnp_rate_measure_t;

static inline void fnp_compute_rate(fnp_rate_measure_t* meas)
{
    if (meas->packet_count == 0)
    {
        printf("No packets received yet.\n");
        return;
    }

    u64 hz = fnp_get_tsc_hz();
    double delay = (double)(meas->last_tsc - meas->first_tsc) / (double)hz;
    double pps = (double)meas->packet_count / delay / 10000.0;
    double Bps = (double)meas->byte_count / delay / 1000000000.0;
    // printf(
    //     "packet count is %llu, byte count is %llu, first tsc is %llu, last tsc is %llu, hz is %llu, delay is %.2lf\n",
    //     meas->packet_count, meas->byte_count, meas->first_tsc, meas->last_tsc, hz, delay);
    printf("pps is %.4lfWpps, Bps is %.4lfGBps, bps is %.4lfGbps\n", pps, Bps, Bps * 8);
    if (meas->file != NULL)
    {
        fprintf(meas->file, "%.4lf %.4lf", pps, Bps);
    }
}


static inline void fnp_update_rate_measure(fnp_rate_measure_t* meas, i32 data_len)
{
    u64 tsc = fnp_get_tsc();
    if (unlikely(meas->packet_count == 0))
    {
        meas->first_tsc = tsc;
    }

    meas->last_tsc = tsc;
    meas->packet_count++;
    meas->byte_count += data_len;

    if (meas->packet_count == meas->interval_count)
    {
        fnp_compute_rate(meas);
        meas->packet_count = 0;
        meas->byte_count = 0;
    }
}


#endif // FNP_COMMON_H
