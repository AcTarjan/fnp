#include "fnp_ifaddr.h"

#include "fnp_context.h"
#include "fnp_error.h"
#include "hash.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define IFADDR_TABLE_SIZE 256
#define ifaddr_context (get_fnp_context()->ifaddr)

static u8 ipv4_mask_prefix_len(u32 mask_be)
{
    u32 mask = rte_be_to_cpu_32(mask_be);
    u8 prefix_len = 0;
    while ((mask & 0x80000000u) != 0)
    {
        ++prefix_len;
        mask <<= 1;
    }

    return prefix_len;
}

static void fill_ifaddr_info(const fnp_ifaddr_t *ifaddr, fnp_ifaddr_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->id = ifaddr->id;
    info->network_id = ifaddr->pool_id;
    info->device_id = ifaddr->dev == NULL ? UINT16_MAX : ifaddr->dev->id;
    info->prefix_len = ifaddr->prefix_len;
    snprintf(info->network_name, sizeof(info->network_name), "%s", ifaddr->pool_name);
    snprintf(info->name, sizeof(info->name), "%s", ifaddr->name == NULL ? "" : ifaddr->name);
    snprintf(info->device_name, sizeof(info->device_name), "%s", ifaddr->dev == NULL ? "" : ifaddr->dev->name);
    info->ip = ifaddr->local_ip_be;
    info->gateway = ifaddr->gateway_be;
}

static u32 pool_first_host_cpu(const fnp_ifaddr_pool_t *pool)
{
    u32 subnet_cpu = rte_be_to_cpu_32(pool->subnet_be);
    return pool->prefix_len <= 30 ? subnet_cpu + 1 : subnet_cpu;
}

static u32 pool_last_host_cpu(const fnp_ifaddr_pool_t *pool)
{
    u32 subnet_cpu = rte_be_to_cpu_32(pool->subnet_be);
    u32 mask_cpu = rte_be_to_cpu_32(pool->netmask_be);
    u32 broadcast_cpu = subnet_cpu | ~mask_cpu;
    return pool->prefix_len <= 30 ? broadcast_cpu - 1 : broadcast_cpu;
}

static bool pool_candidate_usable(const fnp_ifaddr_pool_t *pool, u32 candidate_cpu)
{
    u32 subnet_cpu = rte_be_to_cpu_32(pool->subnet_be);
    u32 mask_cpu = rte_be_to_cpu_32(pool->netmask_be);
    u32 broadcast_cpu = subnet_cpu | ~mask_cpu;
    if ((candidate_cpu & mask_cpu) != subnet_cpu)
    {
        return false;
    }

    if (pool->prefix_len <= 30 &&
        (candidate_cpu == subnet_cpu || candidate_cpu == broadcast_cpu))
    {
        return false;
    }

    return rte_cpu_to_be_32(candidate_cpu) != pool->gateway_be;
}

static int register_ifaddr(fnp_ifaddr_t *ifaddr)
{
    return hash_add(ifaddr_context.ifaddr_tbl, &ifaddr->local_ip_be, ifaddr) ? FNP_OK : FNP_ERR_ADD_HASH;
}

static bool parse_ifaddr_cidr(const char *cidr, u32 *local_ip_be, u32 *netmask_be, u8 *prefix_len)
{
    char buf[64];
    char *slash;
    char *end = NULL;
    long prefix_value;
    struct in_addr addr = {0};
    size_t len;

    if (unlikely(cidr == NULL))
    {
        return false;
    }

    len = strnlen(cidr, sizeof(buf));
    if (len == 0 || len >= sizeof(buf))
    {
        return false;
    }

    memcpy(buf, cidr, len + 1);
    slash = strchr(buf, '/');
    if (slash == NULL)
    {
        return false;
    }

    *slash = '\0';
    prefix_value = strtol(slash + 1, &end, 10);
    if (end == slash + 1 || *end != '\0' || prefix_value < 0 || prefix_value > 32)
    {
        return false;
    }

    if (inet_pton(AF_INET, buf, &addr) != 1)
    {
        return false;
    }

    *local_ip_be = addr.s_addr;
    *prefix_len = (u8)prefix_value;
    if (*prefix_len == 0)
    {
        *netmask_be = 0;
    }
    else if (*prefix_len == 32)
    {
        *netmask_be = UINT32_MAX;
    }
    else
    {
        *netmask_be = rte_cpu_to_be_32(UINT32_MAX << (32 - *prefix_len));
    }

    return true;
}

static fnp_ifaddr_pool_t *find_pool_for_ifaddr(const fnp_device_t *dev,
                                               u32 local_ip_be,
                                               u32 netmask_be)
{
    for (int i = 0; i < ifaddr_context.pool_count; ++i)
    {
        fnp_ifaddr_pool_t *pool = &ifaddr_context.pools[i];
        if (pool->dev == dev &&
            pool->netmask_be == netmask_be &&
            (local_ip_be & netmask_be) == pool->subnet_be)
        {
            return pool;
        }
    }

    return NULL;
}

static int add_static_ifaddr(fnp_device_t *dev, const char *cidr)
{
    u32 local_ip_be = 0;
    u32 netmask_be = 0;
    u8 prefix_len = 0;
    if (unlikely(dev == NULL || !parse_ifaddr_cidr(cidr, &local_ip_be, &netmask_be, &prefix_len)))
    {
        return FNP_ERR_PARAM;
    }

    if (lookup_ifaddr(local_ip_be) != NULL)
    {
        return FNP_ERR_OCCUPIED;
    }

    if (ifaddr_context.ifaddr_count >= FNP_MAX_IFADDR_NUM)
    {
        return FNP_ERR_FULL;
    }

    fnp_ifaddr_pool_t *pool = find_pool_for_ifaddr(dev, local_ip_be, netmask_be);
    fnp_ifaddr_t *ifaddr = &ifaddr_context.ifaddrs[ifaddr_context.ifaddr_count];
    memset(ifaddr, 0, sizeof(*ifaddr));
    ifaddr->id = (u16)ifaddr_context.ifaddr_count;
    ifaddr->pool_id = pool == NULL ? UINT16_MAX : pool->id;
    ifaddr->dev = dev;
    ifaddr->local_ip_be = local_ip_be;
    ifaddr->netmask_be = netmask_be;
    ifaddr->network_be = local_ip_be & netmask_be;
    ifaddr->gateway_be = pool == NULL ? 0 : pool->gateway_be;
    ifaddr->prefix_len = prefix_len;
    if (pool != NULL)
    {
        snprintf(ifaddr->pool_name, sizeof(ifaddr->pool_name), "%s", pool->name);
    }

    char ifaddr_name[FNP_IFADDR_NAME_LEN];
    if (pool != NULL)
    {
        snprintf(ifaddr_name, sizeof(ifaddr_name), "%.24s-%u", pool->name, (unsigned)pool->next_ifaddr_seq++);
    }
    else
    {
        snprintf(ifaddr_name, sizeof(ifaddr_name), "%.24s-%u", dev->name, (unsigned)(ifaddr->id + 1));
    }

    ifaddr->name = fnp_string_duplicate(ifaddr_name);
    ifaddr->ip = fnp_ipv4_ntos(local_ip_be);
    if (ifaddr->name == NULL || ifaddr->ip == NULL)
    {
        fnp_string_free(ifaddr->name);
        fnp_string_free(ifaddr->ip);
        memset(ifaddr, 0, sizeof(*ifaddr));
        return FNP_ERR_MALLOC;
    }

    int ret = register_ifaddr(ifaddr);
    if (ret != FNP_OK)
    {
        fnp_string_free(ifaddr->name);
        fnp_string_free(ifaddr->ip);
        memset(ifaddr, 0, sizeof(*ifaddr));
        return ret;
    }

    ++ifaddr_context.ifaddr_count;

    char *gateway = fnp_ipv4_ntos(ifaddr->gateway_be);
    printf("register static ifaddr on device %s: %s/%u gateway=%s pool=%s\n",
           dev->name,
           ifaddr->ip,
           ifaddr->prefix_len,
           gateway == NULL ? "0.0.0.0" : gateway,
           ifaddr->pool_name[0] == '\0' ? "" : ifaddr->pool_name);
    fnp_string_free(gateway);
    return FNP_OK;
}

int get_fnp_ifaddr_count(void)
{
    return ifaddr_context.ifaddr_count;
}

fnp_ifaddr_t *get_fnp_ifaddr(int index)
{
    if (unlikely(index < 0 || index >= ifaddr_context.ifaddr_count))
    {
        return NULL;
    }

    return &ifaddr_context.ifaddrs[index];
}

fnp_ifaddr_t *lookup_ifaddr(u32 local_ip_be)
{
    fnp_ifaddr_t *ifaddr = NULL;
    if (unlikely(local_ip_be == 0 || ifaddr_context.ifaddr_tbl == NULL))
    {
        return NULL;
    }

    hash_lookup(ifaddr_context.ifaddr_tbl, &local_ip_be, (void **)&ifaddr);
    return ifaddr;
}

fnp_ifaddr_t *lookup_ifaddr_by_id(u16 ifaddr_id)
{
    for (int i = 0; i < ifaddr_context.ifaddr_count; ++i)
    {
        if (ifaddr_context.ifaddrs[i].id == ifaddr_id)
        {
            return &ifaddr_context.ifaddrs[i];
        }
    }

    return NULL;
}

fnp_ifaddr_t *find_ifaddr_on_device(fnp_device_t *dev, u32 local_ip_be)
{
    for (int i = 0; i < ifaddr_context.ifaddr_count; ++i)
    {
        fnp_ifaddr_t *ifaddr = &ifaddr_context.ifaddrs[i];
        if (ifaddr->dev == dev && ifaddr->local_ip_be == local_ip_be)
        {
            return ifaddr;
        }
    }

    return NULL;
}

fnp_ifaddr_t *find_ifaddr_on_device_for_remote(fnp_device_t *dev, u32 remote_ip_be)
{
    fnp_ifaddr_t *first = NULL;
    for (int i = 0; i < ifaddr_context.ifaddr_count; ++i)
    {
        fnp_ifaddr_t *ifaddr = &ifaddr_context.ifaddrs[i];
        if (ifaddr->dev != dev)
        {
            continue;
        }

        if (first == NULL)
        {
            first = ifaddr;
        }

        if ((remote_ip_be & ifaddr->netmask_be) == ifaddr->network_be)
        {
            return ifaddr;
        }
    }

    return first;
}

int export_fnp_ifaddrs(fnp_ifaddr_info_t *infos, u16 info_capacity, u16 *info_count)
{
    if (unlikely(info_count == NULL))
    {
        return FNP_ERR_PARAM;
    }

    *info_count = (u16)ifaddr_context.ifaddr_count;
    if (ifaddr_context.ifaddr_count == 0)
    {
        return FNP_OK;
    }

    if (infos == NULL || info_capacity < ifaddr_context.ifaddr_count)
    {
        return FNP_ERR_FULL;
    }

    for (int i = 0; i < ifaddr_context.ifaddr_count; ++i)
    {
        fill_ifaddr_info(&ifaddr_context.ifaddrs[i], &infos[i]);
    }

    return FNP_OK;
}

int init_fnp_ifaddr_layer(fnp_config *conf)
{
    ifaddr_context.ifaddr_tbl = hash_create("fnp_ifaddr_tbl", IFADDR_TABLE_SIZE, sizeof(u32));
    if (ifaddr_context.ifaddr_tbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    ifaddr_context.ifaddr_count = 0;
    ifaddr_context.pool_count = conf->network.networks_count;
    for (int i = 0; i < conf->network.networks_count; ++i)
    {
        const fnp_network_pool_config *pool_conf = &conf->network.networks[i];
        fnp_device_t *dev = lookup_device_by_name(pool_conf->device);
        if (dev == NULL)
        {
            return FNP_ERR_PARAM;
        }

        fnp_ifaddr_pool_t *pool = &ifaddr_context.pools[i];
        memset(pool, 0, sizeof(*pool));
        pool->id = (u16)i;
        pool->dev = dev;
        snprintf(pool->name, sizeof(pool->name), "%s", pool_conf->name == NULL ? "" : pool_conf->name);
        pool->subnet_be = pool_conf->subnet_be;
        pool->netmask_be = pool_conf->netmask_be;
        pool->gateway_be = pool_conf->gateway_be;
        pool->prefix_len = ipv4_mask_prefix_len(pool_conf->netmask_be);
        pool->priority = pool_conf->priority;
        pool->next_ifaddr_seq = 1;
        pool->next_ip_cpu = pool_first_host_cpu(pool);

        char *subnet = fnp_ipv4_ntos(pool->subnet_be);
        char *gateway = fnp_ipv4_ntos(pool->gateway_be);
        printf("register ifaddr pool %s on %s: %s/%u gateway=%s priority=%d\n",
               pool->name,
               dev->name,
               subnet == NULL ? "0.0.0.0" : subnet,
               pool->prefix_len,
               gateway == NULL ? "0.0.0.0" : gateway,
               pool->priority);
        fnp_string_free(subnet);
        fnp_string_free(gateway);
    }

    for (int i = 0; i < conf->network.devices_count; ++i)
    {
        const fnp_device_config *device_conf = &conf->network.devices[i];
        fnp_device_t *dev = lookup_device_by_name(device_conf->name);
        if (dev == NULL)
        {
            return FNP_ERR_PARAM;
        }

        for (int j = 0; j < device_conf->ifaddrs_count; ++j)
        {
            int ret = add_static_ifaddr(dev, device_conf->ifaddrs[j]);
            CHECK_RET(ret);
        }
    }

    return FNP_OK;
}
