#ifndef FNP_ROUTE_H
#define FNP_ROUTE_H

#include "fnp_ifaddr.h"

typedef enum fnp_route_type
{
    fnp_route_type_connected = 1, // 直连路由，目标就在出口ifaddr所在网段内
    fnp_route_type_gateway,       // 网关路由，需要先发给下一跳网关
} fnp_route_type_t;

// 一条路由表项，表示“某个目标前缀应该从哪个本地ifaddr发出，以及下一跳是谁”。
typedef struct route_entry
{
    u32 prefix_be; // 目标网络前缀（网络序），已经做过 prefix & mask 归一化
    u32 mask_be;   // 子网掩码（网络序）
    u8 prefix_len; // 前缀长度，便于最长前缀匹配
    u8 reserved0;
    u16 reserved1;
    i32 priority;          // 同前缀长度下按 priority 选路；数值越大优先级越高
    u32 next_hop_be;       // 下一跳IP（网络序）；直连路由时为0，表示目的IP本身就是下一跳
    fnp_route_type_t type; // 路由类型：直连或网关
    fnp_ifaddr_t *ifaddr;  // 命中这条路由时使用的本地出口地址
} route_entry_t;

// 路由查找结果，表示“这个目标IP最终应如何发送”。
typedef struct route_result
{
    bool is_local;        // 目标是否就是本机地址；若为true，则应走本地递交
    fnp_ifaddr_t *ifaddr; // 出口本地地址；对本地地址查询则表示命中的本地ifaddr
    u32 next_hop_be;      // 实际二层解析用的下一跳IP（网络序）
    u32 pref_src_be;      // 建议使用的源IP（网络序）
} route_result_t;

int init_route_layer(fnp_config *conf);

// 查询目标IP是否是本机地址；命中时直接返回本地ifaddr。
fnp_ifaddr_t *route_lookup_local(u32 local_ip_be);

// 按普通发送路径查路由，不指定首选出口地址。
int route_lookup(u32 dst_ip_be, route_result_t *result);

// 按指定 preferred_ifaddr 所属 device 查路由，常用于 connected socket 固定出口场景。
int route_lookup_with_ifaddr(fnp_ifaddr_t *preferred_ifaddr, u32 dst_ip_be, route_result_t *result);

#endif // FNP_ROUTE_H
