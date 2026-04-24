#include "ipv4.h"

#include "fnp_context.h"
#include "fnp_worker.h"
#include "ether.h"
#include "arp.h"
#include "route.h"
#include "fsocket.h"

#include <rte_udp.h>
#include <rte_ip.h>

static ipv4_input_func ipv4_input_table[UINT8_MAX + 1];
static ipv4_local_deliver_func ipv4_local_deliver_handler;

static void ipv4_drop_input(struct rte_mbuf *m)
{
    free_mbuf(m);
}

static void ipv4_ignore_local_deliver(struct rte_mbuf *m)
{
    (void)m;
}

// 校验一个以 IPv4 头起始的 mbuf：
// 1. 必须是 IPv4 报文
// 2. total_length 不能越界
// 3. 如果 mbuf 比 IPv4 total_length 更长，则裁剪到真实长度
static struct rte_ipv4_hdr *ipv4_validate_packet(struct rte_mbuf *m)
{
    if (unlikely(m == NULL || m->pkt_len < sizeof(struct rte_ipv4_hdr)))
    {
        return NULL;
    }

    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    u16 header_len = rte_ipv4_hdr_len(hdr);
    u16 total_len = rte_be_to_cpu_16(hdr->total_length);
    if (unlikely((hdr->version_ihl >> 4) != 4 ||
                 header_len < sizeof(struct rte_ipv4_hdr) ||
                 total_len < header_len ||
                 total_len > m->pkt_len))
    {
        return NULL;
    }

    if (unlikely(total_len < m->pkt_len))
    {
        rte_pktmbuf_trim(m, m->pkt_len - total_len);
    }

    return hdr;
}

static inline bool ipv4_is_local_packet(const struct rte_ipv4_hdr *hdr)
{
    return hdr != NULL && route_lookup_local(hdr->dst_addr) != NULL;
}

int init_ipv4_layer(void)
{
    for (u32 i = 0; i <= UINT8_MAX; ++i)
    {
        ipv4_input_table[i] = ipv4_drop_input;
    }

    ipv4_local_deliver_handler = ipv4_ignore_local_deliver;
    return ether_register_input(RTE_ETHER_TYPE_IPV4, ipv4_recv_mbuf);
}

int ipv4_register_input(u8 protocol, ipv4_input_func input)
{
    ipv4_input_table[protocol] = input == NULL ? ipv4_drop_input : input;
    return FNP_OK;
}

int ipv4_register_local_deliver(ipv4_local_deliver_func input)
{
    ipv4_local_deliver_handler = input == NULL ? ipv4_ignore_local_deliver : input;
    return FNP_OK;
}

static void raw_local_deliver(struct rte_mbuf *m)
{
    ipv4_local_deliver_handler(m);
}

static void ipv4_tx_send_default(ipv4_tx_cache_t *cache, struct rte_mbuf *m, u8 proto,
                                 const fsockaddr_t *local, const fsockaddr_t *remote);

static bool ipv4_tx_sockaddr_matches(const fsockaddr_t *requested, const fsockaddr_t *cached)
{
    if (requested == NULL || cached == NULL)
    {
        return false;
    }

    if (requested->family != 0 && requested->family != cached->family)
    {
        return false;
    }

    if (requested->ip != 0 && requested->ip != cached->ip)
    {
        return false;
    }

    return requested->port == 0 || requested->port == cached->port;
}

static bool ipv4_tx_cache_matches(const ipv4_tx_cache_t *cache,
                                  const fsockaddr_t *local,
                                  const fsockaddr_t *remote)
{
    return cache != NULL && cache->ifaddr != NULL &&
           ipv4_tx_sockaddr_matches(local, &cache->local) &&
           ipv4_tx_sockaddr_matches(remote, &cache->remote);
}

static void transport_local_deliver(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    ipv4_input_table[hdr->next_proto_id](m);
}

static void ip_local_deliver(struct rte_mbuf *m)
{
    raw_local_deliver(m);

    transport_local_deliver(m);
}

void ipv4_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    if (unlikely(!ipv4_is_local_packet(hdr)))
    {
        // Forwarding path is not implemented yet.
        free_mbuf(m);
        return;
    }

    ip_local_deliver(m);
}

void ipv4_tun_input(struct rte_mbuf *m)
{
    if (unlikely(ipv4_validate_packet(m) == NULL))
    {
        free_mbuf(m);
        return;
    }

    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    char *src_ip = fnp_ipv4_ntos(hdr->src_addr);
    char *dst_ip = fnp_ipv4_ntos(hdr->dst_addr);
    FNP_DEBUG("ipv4_tun_input: inject proto=%u src=%s dst=%s pkt_len=%u\n",
              hdr->next_proto_id,
              src_ip == NULL ? "0.0.0.0" : src_ip,
              dst_ip == NULL ? "0.0.0.0" : dst_ip,
              m->pkt_len);
    fnp_string_free(src_ip);
    fnp_string_free(dst_ip);
    ipv4_recv_mbuf(m);
}

static inline void compute_cksum(struct rte_ipv4_hdr *hdr, struct rte_mbuf *m)
{
    u16 l3_len = rte_ipv4_hdr_len(hdr);
    switch (hdr->next_proto_id)
    {
    case IPPROTO_UDP:
    {
        struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, l3_len);
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(hdr, udp_hdr);
        break;
    }
    }

    // 计算ipv4头部校验和
    hdr->hdr_checksum = rte_ipv4_cksum(hdr);
}

static inline void ipv4_fill_hdr(struct rte_mbuf *m, u8 proto, u32 src_ip_be, u32 dst_ip_be)
{
    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, IPV4_HDR_LEN);
    hdr->version_ihl = 0x45;
    hdr->type_of_service = 0;
    hdr->total_length = rte_cpu_to_be_16(m->pkt_len);
    hdr->packet_id = 0;
    hdr->fragment_offset = 0;
    hdr->time_to_live = 64;
    hdr->next_proto_id = proto;
    hdr->src_addr = src_ip_be;
    hdr->dst_addr = dst_ip_be;
    hdr->hdr_checksum = 0;
}

static inline void ipv4_prepare_tx_offload(struct rte_mbuf *m, struct rte_ipv4_hdr *hdr, u8 proto)
{
    m->ol_flags = (RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4);
    m->l3_len = IPV4_HDR_LEN;
    if (likely(proto == IPPROTO_UDP))
    {
        m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, IPV4_HDR_LEN);
        udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(hdr, m->ol_flags);
    }
}

static inline void ipv4_prepare_tx_by_dev(struct rte_mbuf *m,
                                          struct rte_ipv4_hdr *hdr,
                                          u8 proto,
                                          const fnp_device_t *dev)
{
    if (is_ethernet_device(dev))
    {
        ipv4_prepare_tx_offload(m, hdr, proto);
        return;
    }

    compute_cksum(hdr, m);
}

static inline void ipv4_send_dev(struct rte_mbuf *m,
                                 fnp_ifaddr_t *ifaddr,
                                 u32 next_hop_be,
                                 const struct rte_ether_addr *dmac)
{
    fnp_device_t *dev = ifaddr == NULL ? NULL : ifaddr->dev;
    if (unlikely(dev == NULL || dev->ops == NULL || dev->ops->send == NULL))
    {
        free_mbuf(m);
        return;
    }

    char *next_hop = fnp_ipv4_ntos(next_hop_be);
    FNP_DEBUG("ipv4_send_dev: dev=%s ifaddr=%s next_hop=%s is_tun=%d pkt_len=%u\n",
              dev->name,
              ifaddr != NULL && ifaddr->ip != NULL ? ifaddr->ip : "unknown",
              next_hop == NULL ? "0.0.0.0" : next_hop,
              is_tun_device(dev),
              m->pkt_len);
    fnp_string_free(next_hop);

    if (is_tun_device(dev))
    {
        dev->ops->send(dev, m, NULL);
        return;
    }

    if (likely(dmac != NULL))
    {
        dev->ops->send(dev, m, dmac);
        return;
    }

    arp_entry_t *arp_entry = arp_lookup(ifaddr, next_hop_be);
    if (unlikely(arp_entry == NULL))
    {
        arp_pend_mbuf(ifaddr, next_hop_be, m);
        return;
    }

    dev->ops->send(dev, m, &arp_entry->mac);
}

static inline void ipv4_local_send_packet(struct rte_mbuf *m, u8 proto, u32 src_ip_be, u32 dst_ip_be)
{
    struct rte_ipv4_hdr *hdr;

    ipv4_fill_hdr(m, proto, src_ip_be, dst_ip_be);
    hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    compute_cksum(hdr, m);
    ip_local_deliver(m);
}

// connected socket 的快速发送路径：
// - 已经缓存了出口 ifaddr、next hop 和 dmac
// - 直接补 IPv4 头后发送，避免再次查路由和 ARP
static void ipv4_tx_send_fast(ipv4_tx_cache_t *cache, struct rte_mbuf *m, u8 proto,
                              const fsockaddr_t *local, const fsockaddr_t *remote)
{
    if (unlikely(cache == NULL || cache->ifaddr == NULL))
    {
        free_mbuf(m);
        return;
    }

    if (unlikely(!ipv4_tx_cache_matches(cache, local, remote)))
    {
        ipv4_tx_cache_init(cache);
        ipv4_tx_send_default(cache, m, proto, local, remote);
        return;
    }

    if (!cache->dmac_ready && cache->ifaddr->dev != NULL && !is_tun_device(cache->ifaddr->dev))
    {
        arp_entry_t *arp_entry = arp_lookup(cache->ifaddr, cache->next_hop_be);
        if (arp_entry != NULL)
        {
            rte_ether_addr_copy(&arp_entry->mac, &cache->dmac);
            cache->dmac_ready = true;
        }
    }

    ipv4_fill_hdr(m, proto, cache->local.ip, cache->remote.ip);
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    ipv4_prepare_tx_by_dev(m, hdr, proto, cache->ifaddr->dev);
    ipv4_send_dev(m, cache->ifaddr, cache->next_hop_be, cache->dmac_ready ? &cache->dmac : NULL);
}

static void ipv4_tx_send_local(ipv4_tx_cache_t *cache, struct rte_mbuf *m, u8 proto,
                               const fsockaddr_t *local, const fsockaddr_t *remote)
{
    if (cache != NULL)
    {
        local = &cache->local;
        remote = &cache->remote;
    }

    if (unlikely(local == NULL || remote == NULL))
    {
        free_mbuf(m);
        return;
    }

    ipv4_local_send_packet(m, proto, local->ip, remote->ip);
}

static void ipv4_tx_send_default(ipv4_tx_cache_t *cache, struct rte_mbuf *m, u8 proto,
                                 const fsockaddr_t *local, const fsockaddr_t *remote)
{
    if (unlikely(remote == NULL))
    {
        free_mbuf(m);
        return;
    }

    u32 remote_ip_be = remote->ip;
    u32 local_ip_be = local == NULL ? 0 : local->ip;
    if (unlikely(remote_ip_be == 0))
    {
        free_mbuf(m);
        return;
    }

    fnp_ifaddr_t *preferred_ifaddr = local_ip_be == 0 ? NULL : lookup_ifaddr(local_ip_be);
    fnp_route_result_t route_result;
    int ret = preferred_ifaddr == NULL ? route_lookup(remote_ip_be, &route_result) : route_lookup_with_ifaddr(preferred_ifaddr, remote_ip_be, &route_result);
    if (unlikely(ret != FNP_OK || route_result.ifaddr == NULL))
    {
        char *dst_ip = fnp_ipv4_ntos(remote_ip_be);
        char *src_ip = fnp_ipv4_ntos(local_ip_be);
        FNP_WARN("ipv4_tx_send_default: route lookup failed ret=%d src=%s dst=%s\n",
                 ret,
                 src_ip == NULL ? "0.0.0.0" : src_ip,
                 dst_ip == NULL ? "0.0.0.0" : dst_ip);
        fnp_string_free(dst_ip);
        fnp_string_free(src_ip);
        free_mbuf(m);
        return;
    }

    u32 src_ip_be = local_ip_be == 0 ? route_result.pref_src_be : local_ip_be;
    if (unlikely(route_result.is_local))
    {
        if (cache != NULL && local != NULL)
        {
            fsockaddr_copy(&cache->local, local);
            cache->local.ip = src_ip_be;
            fsockaddr_copy(&cache->remote, remote);
            cache->send = ipv4_tx_send_local;
        }

        ipv4_local_send_packet(m, proto, src_ip_be, remote_ip_be);
        return;
    }

    {
        char *dst_ip = fnp_ipv4_ntos(remote_ip_be);
        char *src_ip = fnp_ipv4_ntos(src_ip_be);
        char *pref_ip = fnp_ipv4_ntos(local_ip_be);
        char *next_hop = fnp_ipv4_ntos(route_result.next_hop_be);
        FNP_DEBUG("ipv4_tx_send_default: preferred_src=%s final_src=%s dst=%s route_dev=%s route_ifaddr=%s next_hop=%s is_local=%d\n",
                  pref_ip == NULL ? "0.0.0.0" : pref_ip,
                  src_ip == NULL ? "0.0.0.0" : src_ip,
                  dst_ip == NULL ? "0.0.0.0" : dst_ip,
                  route_result.ifaddr->dev == NULL ? "unknown" : route_result.ifaddr->dev->name,
                  route_result.ifaddr->ip == NULL ? "unknown" : route_result.ifaddr->ip,
                  next_hop == NULL ? "0.0.0.0" : next_hop,
                  route_result.is_local);
        fnp_string_free(dst_ip);
        fnp_string_free(src_ip);
        fnp_string_free(pref_ip);
        fnp_string_free(next_hop);
    }
    ipv4_fill_hdr(m, proto, src_ip_be, remote_ip_be);
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    ipv4_prepare_tx_by_dev(m, hdr, proto, route_result.ifaddr->dev);

    if (cache != NULL && local != NULL)
    {
        fsockaddr_copy(&cache->local, local);
        fsockaddr_copy(&cache->remote, remote);
        cache->ifaddr = route_result.ifaddr;
        cache->next_hop_be = route_result.next_hop_be;
        cache->dmac_ready = false;
        if (route_result.ifaddr->dev != NULL &&
            !is_tun_device(route_result.ifaddr->dev))
        {
            arp_entry_t *arp_entry = arp_lookup(route_result.ifaddr, route_result.next_hop_be);
            if (arp_entry != NULL)
            {
                rte_ether_addr_copy(&arp_entry->mac, &cache->dmac);
                cache->dmac_ready = true;
            }
        }
        cache->send = ipv4_tx_send_fast;
    }

    ipv4_send_dev(m, route_result.ifaddr, route_result.next_hop_be, cache != NULL && cache->dmac_ready ? &cache->dmac : NULL);
}

void ipv4_send_default(struct rte_mbuf *m, u8 proto, const fsockaddr_t *local, const fsockaddr_t *remote)
{
    ipv4_tx_send_default(NULL, m, proto, local, remote);
}

void ipv4_tx_cache_init(ipv4_tx_cache_t *cache)
{
    if (cache == NULL)
    {
        return;
    }

    memset(cache, 0, sizeof(*cache));
    cache->send = ipv4_tx_send_default;
}

void ipv4_tx_cache_send(ipv4_tx_cache_t *cache, struct rte_mbuf *m, u8 proto,
                        const fsockaddr_t *local, const fsockaddr_t *remote)
{
    if (unlikely(cache == NULL))
    {
        ipv4_send_default(m, proto, local, remote);
        return;
    }

    if (cache->send != ipv4_tx_send_default && !ipv4_tx_cache_matches(cache, local, remote))
    {
        ipv4_tx_cache_init(cache);
    }

    cache->send(cache, m, proto, local, remote);
}

void ipv4_send_mbuf(struct rte_mbuf *m, u8 proto, u32 rip)
{
    fsockaddr_t remote = {
        .family = FSOCKADDR_IPV4,
        .ip = rip,
    };
    ipv4_send_default(m, proto, NULL, &remote);
}

void ipv4_send_raw_mbuf(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = ipv4_validate_packet(m);
    if (unlikely(hdr == NULL))
    {
        free_mbuf(m);
        return;
    }

    fnp_ifaddr_t *preferred_ifaddr = NULL;
    if (hdr->src_addr != 0)
    {
        preferred_ifaddr = lookup_ifaddr(hdr->src_addr);
        if (preferred_ifaddr == NULL)
        {
            free_mbuf(m);
            return;
        }
    }

    fnp_route_result_t route_result;
    int ret = preferred_ifaddr != NULL ? route_lookup_with_ifaddr(preferred_ifaddr, hdr->dst_addr, &route_result) : route_lookup(hdr->dst_addr, &route_result);
    if (unlikely(ret != FNP_OK || route_result.ifaddr == NULL))
    {
        free_mbuf(m);
        return;
    }

    if (hdr->src_addr == 0)
    {
        hdr->src_addr = route_result.pref_src_be;
    }

    if (unlikely(route_result.is_local))
    {
        compute_cksum(hdr, m);
        ip_local_deliver(m);
        return;
    }

    ipv4_prepare_tx_by_dev(m, hdr, hdr->next_proto_id, route_result.ifaddr->dev);
    ipv4_send_dev(m, route_result.ifaddr, route_result.next_hop_be, NULL);
}
