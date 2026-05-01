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

int ipv4_register_local_deliver(ipv4_local_deliver_func input)
{
    ipv4_local_deliver_handler = input == NULL ? ipv4_ignore_local_deliver : input;
    return FNP_OK;
}

static void raw_local_deliver(struct rte_mbuf *m)
{
    ipv4_local_deliver_handler(m);
}

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
           ipv4_tx_sockaddr_matches(local, &cache->src) &&
           ipv4_tx_sockaddr_matches(remote, &cache->dst);
}

static void transport_local_deliver(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
    ipv4_input_table[hdr->next_proto_id](m);
}

static void ip_local_deliver(struct rte_mbuf *m)
{
    // raw_local_deliver(m);

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

static inline struct rte_ipv4_hdr *ipv4_fill_hdr(struct rte_mbuf *m, u8 proto,
                                                 u32 src_ip_be, u32 dst_ip_be)
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

    return hdr;
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

static inline void ipv4_fill_cksum(struct rte_mbuf *m,
                                   struct rte_ipv4_hdr *hdr,

                                   const fnp_device_t *dev)
{
    if (likely(is_ethernet_device(dev)))
    {
        ipv4_prepare_tx_offload(m, hdr, hdr->next_proto_id);
        return;
    }

    compute_cksum(hdr, m);
}

void ipv4_init_tx_cache(ipv4_tx_cache_t *cache, u8 proto, fsockaddr_t *src, fsockaddr_t *dst)
{
    cache->src = *src;
    cache->dst = *dst;
    cache->proto = proto;
    cache->ready = false;
    cache->ifaddr = NULL;
    cache->next_hop_be = 0;
    memset(&cache->dmac, 0, sizeof(struct rte_ether_addr));
}

// 所有信息都已经确认
static bool ipv4_send_mbuf_with_cache_fast(ipv4_tx_cache_t *cache, struct rte_mbuf *m)
{
    // 填充IPv4头部
    struct rte_ipv4_hdr *hdr = ipv4_fill_hdr(m, cache->proto, cache->src.ip, cache->dst.ip);

    // 计算校验和
    fnp_device_t *dev = cache->ifaddr->dev;
    ipv4_fill_cksum(m, hdr, dev);

    // 发送出去
    return dev->ops->send(dev, m, &cache->dmac);
}

// 信息还未确定
static bool ipv4_send_mbuf_with_cache_default(ipv4_tx_cache_t *cache, struct rte_mbuf *m)
{

    // 如果源IP在本地有绑定地址，则优先使用该地址进行路由查询，以提高命中本地ifaddr的概率，进而走fast路径；否则正常路由查询
    // 本地IP可能与出口网卡不一致
    if (unlikely(cache->next_hop_be == 0))
    {
        // 还没有路由信息，先查路由
        route_result_t route_result;
        int ret = route_lookup(cache->dst.ip, &route_result);
        if (unlikely(ret != FNP_OK))
        {
            char *dst_ip = fnp_ipv4_ntos(cache->dst.ip);
            char *src_ip = fnp_ipv4_ntos(cache->src.ip);
            FNP_WARN("ipv4_tx_send_default: route lookup failed ret=%d src=%s dst=%s\n",
                     ret, src_ip == NULL ? "0.0.0.0" : src_ip, dst_ip == NULL ? "0.0.0.0" : dst_ip);
            fnp_string_free(dst_ip);
            fnp_string_free(src_ip);
            free_mbuf(m);
            return false;
        }

        if (cache->src.ip == 0)
            cache->src.ip = route_result.pref_src_be;
        cache->next_hop_be = route_result.next_hop_be;
        cache->ifaddr = route_result.ifaddr;

        if (unlikely(route_result.is_local))
        {
            // 本地递交, 暂不存在
            // ipv4_local_send_packet(m, proto, src_ip_be, remote_ip_be);
            return true;
        }
    }

    struct rte_ipv4_hdr *hdr = ipv4_fill_hdr(m, cache->proto, cache->src.ip, cache->dst.ip);
    fnp_device_t *dev = cache->ifaddr->dev;
    ipv4_fill_cksum(m, hdr, dev);

    // 确定下一跳MAC地址
    arp_entry_t *arp_entry = arp_lookup(cache->ifaddr, cache->next_hop_be);
    if (arp_entry != NULL)
    {
        rte_ether_addr_copy(&arp_entry->mac, &cache->dmac);
        cache->ready = true;
    }
    else
    {
        // ARP未准备好，先发ARP请求并把这个包挂起；等ARP回复时会走fast路径重试发送
        arp_pend_mbuf(cache->ifaddr, cache->next_hop_be, m);
        return true;
    }

    // 发送出去
    return dev->ops->send(dev, m, &cache->dmac);
}

bool ipv4_send_mbuf_with_cache(ipv4_tx_cache_t *cache, struct rte_mbuf *m)
{
    if (likely(cache->ready))
    {
        return ipv4_send_mbuf_with_cache_fast(cache, m);
    }

    return ipv4_send_mbuf_with_cache_default(cache, m);
}

bool ipv4_send_default(struct rte_mbuf *m, u8 proto, const fsockaddr_t *local, const fsockaddr_t *remote)
{
    if (unlikely(m == NULL || remote == NULL))
    {
        free_mbuf(m);
        return false;
    }

    fsockaddr_t src = {0};
    fsockaddr_t dst = {0};
    if (local != NULL)
    {
        src = *local;
    }
    dst = *remote;

    ipv4_tx_cache_t cache;
    ipv4_init_tx_cache(&cache, proto, &src, &dst);
    return ipv4_send_mbuf_with_cache(&cache, m);
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

    route_result_t route_result;
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

    ipv4_fill_cksum(m, hdr, route_result.ifaddr->dev);

    arp_entry_t *arp_entry = arp_lookup(route_result.ifaddr, route_result.next_hop_be);
    if (arp_entry != NULL)
    {
        route_result.ifaddr->dev->ops->send(route_result.ifaddr->dev, m, &arp_entry->mac);
        return;
    }

    arp_pend_mbuf(route_result.ifaddr, route_result.next_hop_be, m);
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
