#include "route.h"

#include "fnp_context.h"
#include "fnp_error.h"

#include <string.h>

#define FNP_ROUTE_TABLE_MAX 64

typedef struct route_context
{
    int count;
    route_entry_t entries[FNP_ROUTE_TABLE_MAX];
} route_context_t;

static route_context_t route_context;

// 判断目标IP是否命中某条路由项的前缀。
static bool route_ip_match(u32 dst_ip_be, const route_entry_t* entry)
{
    return entry != NULL && (dst_ip_be & entry->mask_be) == entry->prefix_be;
}

// 向当前内存路由表中插入一条路由，并预先计算前缀长度，便于后续最长前缀匹配。
static int route_add_entry(u32 prefix_be, u32 mask_be, u32 next_hop_be,
                           fnp_route_type_t type, fnp_ifaddr_t* ifaddr)
{
    if (route_context.count >= FNP_ROUTE_TABLE_MAX || ifaddr == NULL)
    {
        return FNP_ERR_PARAM;
    }

    route_entry_t* entry = &route_context.entries[route_context.count++];
    memset(entry, 0, sizeof(*entry));
    entry->prefix_be = prefix_be & mask_be;
    entry->mask_be = mask_be;
    entry->prefix_len = 0;
    u32 mask = rte_be_to_cpu_32(mask_be);
    while ((mask & 0x80000000u) != 0)
    {
        ++entry->prefix_len;
        mask <<= 1;
    }
    entry->next_hop_be = next_hop_be;
    entry->type = type;
    entry->ifaddr = ifaddr;
    return FNP_OK;
}

// 为每个本地地址自动生成一条直连路由。
static int route_add_connected(fnp_ifaddr_t* ifaddr)
{
    return route_add_entry(ifaddr->network_be, ifaddr->netmask_be, 0, fnp_route_type_connected, ifaddr);
}

// 根据配置生成默认路由，next hop 指向网关地址。
static int route_add_default(fnp_ifaddr_t* ifaddr, u32 gateway_be)
{
    return route_add_entry(0, 0, gateway_be, fnp_route_type_gateway, ifaddr);
}

// 根据 routes 配置中的 dev/src/via，解析出这条路由实际绑定的出口本地地址。
static fnp_ifaddr_t* route_resolve_ifaddr(const fnp_route_config* route_conf)
{
    fnp_device_t* dev = lookup_device_by_name(route_conf->dev);
    if (dev == NULL)
    {
        return NULL;
    }

    if (route_conf->src_be != 0)
    {
        return find_ifaddr_on_device(dev, route_conf->src_be);
    }

    if (route_conf->via_be != 0)
    {
        fnp_ifaddr_t* ifaddr = find_ifaddr_on_device_for_remote(dev, route_conf->via_be);
        if (ifaddr == NULL || (route_conf->via_be & ifaddr->netmask_be) != ifaddr->network_be)
        {
            return NULL;
        }
        return ifaddr;
    }

    return find_ifaddr_on_device_for_remote(dev, route_conf->dst_ip_be);
}

// 执行最长前缀匹配；如果给定 preferred_ifaddr，则仅在同一 device 上挑选路由。
static route_entry_t* route_lookup_best(fnp_ifaddr_t* preferred_ifaddr, u32 dst_ip_be)
{
    route_entry_t* best = NULL;
    for (int i = 0; i < route_context.count; ++i)
    {
        route_entry_t* entry = &route_context.entries[i];
        if (!route_ip_match(dst_ip_be, entry))
        {
            continue;
        }

        if (preferred_ifaddr != NULL && entry->ifaddr->dev != preferred_ifaddr->dev)
        {
            continue;
        }

        if (best == NULL || entry->prefix_len > best->prefix_len)
        {
            best = entry;
        }
    }

    return best;
}

// 初始化路由模块：
// 1. 先根据所有 ifaddr 自动生成直连路由；
// 2. 再加载配置中的静态路由和默认路由。
int init_route_layer(fnp_config* conf)
{
    memset(&route_context, 0, sizeof(route_context));

    for (int i = 0; i < get_fnp_ifaddr_count(); ++i)
    {
        fnp_ifaddr_t* ifaddr = get_fnp_ifaddr(i);
        int ret = route_add_connected(ifaddr);
        CHECK_RET(ret);
    }

    if (conf != NULL)
    {
        for (int i = 0; i < conf->network.routes_count; ++i)
        {
            const fnp_route_config* route_conf = &conf->network.routes[i];
            fnp_ifaddr_t* ifaddr = route_resolve_ifaddr(route_conf);
            if (ifaddr == NULL)
            {
                return FNP_ERR_PARAM;
            }

            int ret;
            if (route_conf->dst_mask_be == 0 && route_conf->via_be != 0)
            {
                ret = route_add_default(ifaddr, route_conf->via_be);
            }
            else
            {
                ret = route_add_entry(route_conf->dst_ip_be,
                                      route_conf->dst_mask_be,
                                      route_conf->via_be,
                                      route_conf->via_be == 0 ? fnp_route_type_connected : fnp_route_type_gateway,
                                      ifaddr);
            }
            CHECK_RET(ret);
        }
    }

    return FNP_OK;
}

// 本地地址查询，只判断目标IP是否属于本机。
fnp_ifaddr_t* route_lookup_local(u32 local_ip_be)
{
    return lookup_ifaddr(local_ip_be);
}

// 路由查找主流程：
// 1. 先查本地地址；
// 2. 未命中则按最长前缀匹配查找出口路由；
// 3. 返回出口 ifaddr、next hop 和建议源地址。
int route_lookup_with_ifaddr(fnp_ifaddr_t* preferred_ifaddr, u32 dst_ip_be, fnp_route_result_t* result)
{
    if (result == NULL)
    {
        return FNP_ERR_PARAM;
    }

    memset(result, 0, sizeof(*result));
    fnp_ifaddr_t* local_ifaddr = route_lookup_local(dst_ip_be);
    if (local_ifaddr != NULL)
    {
        result->is_local = true;
        result->ifaddr = local_ifaddr;
        result->next_hop_be = dst_ip_be;
        result->pref_src_be = local_ifaddr->local_ip_be;
        return FNP_OK;
    }

    route_entry_t* entry = route_lookup_best(preferred_ifaddr, dst_ip_be);
    if (entry == NULL)
    {
        return FNP_ERR_NOT_FOUND;
    }

    result->is_local = false;
    result->ifaddr = preferred_ifaddr != NULL ? preferred_ifaddr : entry->ifaddr;
    result->next_hop_be = entry->next_hop_be != 0 ? entry->next_hop_be : dst_ip_be;
    result->pref_src_be = result->ifaddr->local_ip_be;
    return FNP_OK;
}

// 普通路由查找入口，不指定首选出口地址。
int route_lookup(u32 dst_ip_be, fnp_route_result_t* result)
{
    return route_lookup_with_ifaddr(NULL, dst_ip_be, result);
}
