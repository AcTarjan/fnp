#include "route.h"

#include "fnp_context.h"
#include "fnp_error.h"

#include <rte_hash.h>
#include <rte_hash_crc.h>

#include <string.h>

#define FNP_ROUTE_TABLE_MAX 1024
#define FNP_ROUTE_PRIORITY_AUTO 0
#define FNP_ROUTE_PREFIX_LEN_MAX 32

typedef struct route_bucket
{
    u32 prefix_be;
    u8 prefix_len;
    u8 reserved0;
    u16 reserved1;
    int first_entry;
    int last_entry;
    route_entry_t *best;
} route_bucket_t;

typedef struct route_context
{
    int count; // 当前有效路由项数量
    int bucket_count;
    route_entry_t entries[FNP_ROUTE_TABLE_MAX];
    int bucket_next[FNP_ROUTE_TABLE_MAX];
    route_bucket_t buckets[FNP_ROUTE_TABLE_MAX];
    struct rte_hash *prefix_tables[FNP_ROUTE_PREFIX_LEN_MAX + 1];
} route_context_t;

static route_context_t route_context;
static u32 route_prefix_masks[FNP_ROUTE_PREFIX_LEN_MAX + 1];

static bool route_entry_matches_preferred(const route_entry_t *entry, const fnp_ifaddr_t *preferred_ifaddr)
{
    return entry != NULL && preferred_ifaddr != NULL && entry->ifaddr != NULL &&
           entry->ifaddr->dev == preferred_ifaddr->dev;
}

// 判断目标IP是否命中某条路由项。
// 命中条件是：(dst & mask) == prefix。
static bool route_ip_match(u32 dst_ip_be, const route_entry_t *entry)
{
    return entry != NULL && (dst_ip_be & entry->mask_be) == entry->prefix_be;
}

static struct rte_hash *route_create_prefix_table(u8 prefix_len)
{
    char name[32] = {0};
    snprintf(name, sizeof(name), "fnp_route_pfx_%u", prefix_len);

    struct rte_hash_parameters params = {
        .name = name,
        .entries = FNP_ROUTE_TABLE_MAX,
        .key_len = sizeof(u32),
        .hash_func = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
    };

    return rte_hash_create(&params);
}

static route_bucket_t *route_lookup_bucket(u8 prefix_len, u32 prefix_be)
{
    if (prefix_len > FNP_ROUTE_PREFIX_LEN_MAX)
    {
        return NULL;
    }

    struct rte_hash *table = route_context.prefix_tables[prefix_len];
    if (table == NULL)
    {
        return NULL;
    }

    route_bucket_t *bucket = NULL;
    if (rte_hash_lookup_data(table, &prefix_be, (void **)&bucket) < 0)
    {
        return NULL;
    }

    return bucket;
}

static route_bucket_t *route_lookup_or_create_bucket(u8 prefix_len, u32 prefix_be)
{
    route_bucket_t *bucket = route_lookup_bucket(prefix_len, prefix_be);
    if (bucket != NULL)
    {
        return bucket;
    }

    if (route_context.bucket_count >= FNP_ROUTE_TABLE_MAX)
    {
        return NULL;
    }

    bucket = &route_context.buckets[route_context.bucket_count++];
    memset(bucket, 0, sizeof(*bucket));
    bucket->prefix_be = prefix_be;
    bucket->prefix_len = prefix_len;
    bucket->first_entry = -1;
    bucket->last_entry = -1;

    if (rte_hash_add_key_data(route_context.prefix_tables[prefix_len], &bucket->prefix_be, bucket) < 0)
    {
        route_context.bucket_count--;
        return NULL;
    }

    return bucket;
}

static void route_bucket_append(route_bucket_t *bucket, int entry_index)
{
    route_context.bucket_next[entry_index] = -1;
    if (bucket->first_entry < 0)
    {
        bucket->first_entry = entry_index;
        bucket->last_entry = entry_index;
        return;
    }

    route_context.bucket_next[bucket->last_entry] = entry_index;
    bucket->last_entry = entry_index;
}

static bool route_entry_better_than(const route_entry_t *candidate,
                                    const route_entry_t *best,
                                    const fnp_ifaddr_t *preferred_ifaddr)
{
    if (candidate == NULL)
    {
        return false;
    }

    if (best == NULL)
    {
        return true;
    }

    if (candidate->priority != best->priority)
    {
        return candidate->priority > best->priority;
    }

    return route_entry_matches_preferred(candidate, preferred_ifaddr) &&
           !route_entry_matches_preferred(best, preferred_ifaddr);
}

static route_entry_t *route_bucket_pick(route_bucket_t *bucket, fnp_ifaddr_t *preferred_ifaddr)
{
    if (bucket == NULL)
    {
        return NULL;
    }

    if (preferred_ifaddr == NULL)
    {
        return bucket->best;
    }

    route_entry_t *best = NULL;
    for (int entry_index = bucket->first_entry;
         entry_index >= 0;
         entry_index = route_context.bucket_next[entry_index])
    {
        route_entry_t *entry = &route_context.entries[entry_index];
        if (route_entry_better_than(entry, best, preferred_ifaddr))
        {
            best = entry;
        }
    }

    return best;
}

// 向内存路由表中插入一条路由项。
// 这里会把 prefix 先和 mask 归一化，并预先计算 prefix_len，
// 这样后续查表时只需要做最长前缀匹配即可。
static int route_add_entry(u32 prefix_be, u32 mask_be, u32 next_hop_be,
                           fnp_route_type_t type, i32 priority, fnp_ifaddr_t *ifaddr)
{
    if (route_context.count >= FNP_ROUTE_TABLE_MAX || ifaddr == NULL)
    {
        return FNP_ERR_PARAM;
    }

    route_entry_t *entry = &route_context.entries[route_context.count++];
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
    entry->priority = priority;
    entry->next_hop_be = next_hop_be;
    entry->type = type;
    entry->ifaddr = ifaddr;

    route_bucket_t *bucket = route_lookup_or_create_bucket(entry->prefix_len, entry->prefix_be);
    if (bucket == NULL)
    {
        route_context.count--;
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    int entry_index = route_context.count - 1;
    route_bucket_append(bucket, entry_index);
    if (route_entry_better_than(entry, bucket->best, NULL))
    {
        bucket->best = entry;
    }

    return FNP_OK;
}

// 为每个本地地址自动生成一条直连路由。
static int route_add_connected(fnp_ifaddr_t *ifaddr)
{
    if (ifaddr == NULL)
    {
        return FNP_ERR_PARAM;
    }

    return route_add_entry(ifaddr->network_be, ifaddr->netmask_be, 0,
                           fnp_route_type_connected, FNP_ROUTE_PRIORITY_AUTO, ifaddr);
}

// 生成默认路由。
// 默认路由的前缀是 0.0.0.0/0，下一跳是配置中的网关地址。
static int route_add_default(fnp_ifaddr_t *ifaddr, u32 gateway_be, i32 priority)
{
    return route_add_entry(0, 0, gateway_be, fnp_route_type_gateway, priority, ifaddr);
}

// 根据 routes 配置中的 dev/src/via，解析这条路由应绑定到哪个本地 ifaddr。
// 规则：
// 1. 如果显式配置了 src，则优先用该 src；
// 2. 否则如果配置了 via，则在指定 device 上找一个和 via 同网段的 ifaddr；
// 3. 否则按目的地址 dst 去找指定 device 上最合适的 ifaddr。
static fnp_ifaddr_t *route_resolve_ifaddr(const fnp_route_config *route_conf)
{
    fnp_device_t *dev = lookup_device_by_name(route_conf->dev);
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
        fnp_ifaddr_t *ifaddr = find_ifaddr_on_device_for_remote(dev, route_conf->via_be);
        if (ifaddr == NULL || (route_conf->via_be & ifaddr->netmask_be) != ifaddr->network_be)
        {
            return NULL;
        }
        return ifaddr;
    }

    return find_ifaddr_on_device_for_remote(dev, route_conf->dst_ip_be);
}

static fnp_ifaddr_t *route_pick_local_source(fnp_ifaddr_t *preferred_ifaddr, fnp_ifaddr_t *target_ifaddr)
{
    if (target_ifaddr == NULL)
    {
        return NULL;
    }

    if (preferred_ifaddr != NULL && preferred_ifaddr->local_ip_be != target_ifaddr->local_ip_be)
    {
        return preferred_ifaddr;
    }

    fnp_ifaddr_t *same_network = NULL;
    fnp_ifaddr_t *same_device = NULL;
    for (int i = 0; i < get_fnp_ifaddr_count(); ++i)
    {
        fnp_ifaddr_t *candidate = get_fnp_ifaddr(i);
        if (candidate == NULL ||
            candidate->local_ip_be == target_ifaddr->local_ip_be ||
            candidate->dev != target_ifaddr->dev)
        {
            continue;
        }

        if (same_device == NULL)
        {
            same_device = candidate;
        }

        if (candidate->network_be == target_ifaddr->network_be &&
            candidate->netmask_be == target_ifaddr->netmask_be)
        {
            same_network = candidate;
            break;
        }
    }

    if (same_network != NULL)
    {
        return same_network;
    }

    if (same_device != NULL)
    {
        return same_device;
    }

    return target_ifaddr;
}

// 执行最长前缀匹配。
// 选路首先只看目标地址：
// 1. 更长前缀优先；
// 2. 同前缀长度下，priority 更高的路由优先；
// 3. 如果 prefix/priority 都相同，再把 preferred_ifaddr 当作软偏好，
//    仅用于在同等级路由之间优先选择同一 device；
// 4. 若仍然完全相同，则保留先入表的路由。
static route_entry_t *route_lookup_best(fnp_ifaddr_t *preferred_ifaddr, u32 dst_ip_be)
{
    for (int prefix_len = FNP_ROUTE_PREFIX_LEN_MAX; prefix_len >= 0; --prefix_len)
    {
        u32 prefix_be = dst_ip_be & route_prefix_masks[prefix_len];
        route_bucket_t *bucket = route_lookup_bucket((u8)prefix_len, prefix_be);
        if (bucket == NULL)
        {
            continue;
        }

        return route_bucket_pick(bucket, preferred_ifaddr);
    }

    return NULL;
}

// 初始化路由模块：
// 1. 先根据所有本地 ifaddr 自动生成直连路由；
// 2. 再加载配置中的静态路由和默认路由。
//
// 当前实现是一个简单的内存数组：
// - 路由项数量不大时足够直接
// - 查找时做线性扫描 + 最长前缀匹配
// 后续如果路由项增多，再考虑替换为 LPM/Trie。
int init_route_layer(fnp_config *conf)
{
    memset(&route_context, 0, sizeof(route_context));
    for (int i = 0; i <= FNP_ROUTE_PREFIX_LEN_MAX; ++i)
    {
        route_context.bucket_next[i] = -1;
    }

    route_prefix_masks[0] = 0;
    for (int prefix_len = 1; prefix_len <= FNP_ROUTE_PREFIX_LEN_MAX; ++prefix_len)
    {
        route_prefix_masks[prefix_len] = rte_cpu_to_be_32(~((1u << (32 - prefix_len)) - 1u));
    }

    for (int prefix_len = 0; prefix_len <= FNP_ROUTE_PREFIX_LEN_MAX; ++prefix_len)
    {
        route_context.prefix_tables[prefix_len] = route_create_prefix_table((u8)prefix_len);
        if (route_context.prefix_tables[prefix_len] == NULL)
        {
            return FNP_ERR_CREATE_HASH_TABLE;
        }
    }

    for (int i = 0; i < FNP_ROUTE_TABLE_MAX; ++i)
    {
        route_context.bucket_next[i] = -1;
    }

    for (int i = 0; i < get_fnp_ifaddr_count(); ++i)
    {
        fnp_ifaddr_t *ifaddr = get_fnp_ifaddr(i);
        int ret = route_add_connected(ifaddr);
        CHECK_RET(ret);
    }

    if (conf != NULL)
    {
        for (int i = 0; i < conf->network.routes_count; ++i)
        {
            const fnp_route_config *route_conf = &conf->network.routes[i];
            fnp_ifaddr_t *ifaddr = route_resolve_ifaddr(route_conf);
            if (ifaddr == NULL)
            {
                return FNP_ERR_PARAM;
            }

            int ret;
            if (route_conf->dst_mask_be == 0 && route_conf->via_be != 0)
            {
                ret = route_add_default(ifaddr, route_conf->via_be, route_conf->priority);
            }
            else
            {
                ret = route_add_entry(route_conf->dst_ip_be,
                                      route_conf->dst_mask_be,
                                      route_conf->via_be,
                                      route_conf->via_be == 0 ? fnp_route_type_connected : fnp_route_type_gateway,
                                      route_conf->priority,
                                      ifaddr);
            }
            CHECK_RET(ret);
        }
    }

    return FNP_OK;
}

// 本地地址查询，只判断目标IP是否属于本机。
// 命中时返回对应的 ifaddr，供 IPv4 本地递交使用。
fnp_ifaddr_t *route_lookup_local(u32 local_ip_be)
{
    return lookup_ifaddr(local_ip_be);
}

// 路由查找主流程：
// 1. 先判断目标是否是本机地址；
// 2. 如果不是本机地址，再按最长前缀匹配查路由；
// 3. preferred_ifaddr 只作为同等级路由之间的软偏好，不直接决定出口；
// 4. 输出发送所需的三个关键信息：
//    - ifaddr：从哪个本地地址发
//    - next_hop_be：下一跳IP是谁
//    - pref_src_be：源IP应该填什么
int route_lookup_with_ifaddr(fnp_ifaddr_t *preferred_ifaddr, u32 dst_ip_be, route_result_t *result)
{
    if (unlikely(result == NULL))
    {
        return FNP_ERR_PARAM;
    }

    memset(result, 0, sizeof(*result));
    fnp_ifaddr_t *local_ifaddr = route_lookup_local(dst_ip_be);
    if (local_ifaddr != NULL)
    {
        fnp_ifaddr_t *source_ifaddr = route_pick_local_source(preferred_ifaddr, local_ifaddr);
        result->is_local = true;
        result->ifaddr = local_ifaddr;
        result->next_hop_be = dst_ip_be;
        result->pref_src_be = source_ifaddr == NULL ? local_ifaddr->local_ip_be : source_ifaddr->local_ip_be;
        return FNP_OK;
    }

    route_entry_t *entry = route_lookup_best(preferred_ifaddr, dst_ip_be);
    if (entry == NULL)
    {
        return FNP_ERR_NOT_FOUND;
    }

    result->is_local = false;
    result->ifaddr = entry->ifaddr;
    result->next_hop_be = entry->next_hop_be != 0 ? entry->next_hop_be : dst_ip_be;
    result->pref_src_be = result->ifaddr->local_ip_be;
    return FNP_OK;
}

// 普通路由查找入口，不指定首选出口地址，不考虑源地址偏好。
int route_lookup(u32 dst_ip_be, route_result_t *result)
{
    return route_lookup_with_ifaddr(NULL, dst_ip_be, result);
}
