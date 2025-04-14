#include "arp.h"
#include "fnp_context.h"
#include "ether.h"

#include <unistd.h>

#include <rte_arp.h>
#include <rte_malloc.h>

#define ARP_HDR_LEN 28
#define ARP_TABLE_SIZE 256

static struct rte_ether_addr broadcast = {0xFF, 0xFF, 0xFF,
                                          0xFF, 0xFF, 0xFF};

typedef struct arp_entry_t
{
    fnp_pring *pending;
    fnp_iface_t *iface;
    u64 tsc;
    u32 ip; // 网络序，大端
    struct rte_ether_addr mac;
    u16 valid;
} arp_entry_t;

int init_arp_layer()
{
    fnp.arpTbl = hash_create("ArpSocketTable", ARP_TABLE_SIZE, 4);
    if (unlikely(fnp.arpTbl == NULL))
    {
        printf("alloc arp table error!\n");
        return -1;
    }

    return 0;
}

static arp_entry_t *arp_insert_entry(fnp_iface_t *iface, u32 ip, struct rte_ether_addr *mac)
{
    arp_entry_t *e = NULL;

    // can't find
    if (unlikely(!hash_lookup(fnp.arpTbl, &ip, &e)))
    {
        e = fnp_malloc(sizeof(arp_entry_t));
        if (unlikely(e == NULL))
        {
            printf("malloc arp_entry_t failed!\n");
            return NULL;
        }

        e->pending = fnp_pring_alloc(8 * 128);
        if (unlikely(e == NULL))
        {
            printf("malloc arp pending failed!\n");
            fnp_free(e);
            return NULL;
        }
    }

    e->ip = ip;
    e->valid = 0;
    if (mac != NULL)
    {
        e->tsc = rte_rdtsc();
        e->iface = iface;
        rte_ether_addr_copy(mac, &e->mac);
        e->valid = 1;
    }

    if (likely(!hash_add(fnp.arpTbl, &ip, e)))
    {
        printf("fail to add %u in gArpTable\n", ip);
        fnp_pring_free(e->pending);
        fnp_free(e);
        return NULL;
    }

    return e;
}

static void arp_del_entry(arp_entry_t *e)
{
    hash_del(fnp.arpTbl, &e->ip);
    fnp_pring_free(e->pending);
    fnp_free(e);
}

static arp_entry_t *arp_lookup(u32 ip)
{
    arp_entry_t *e = NULL;

    hash_lookup(fnp.arpTbl, &ip, &e);

    return e;
}

struct rte_ether_addr *arp_get_mac(u32 ip)
{
    arp_entry_t *e = arp_lookup(ip);
    if (e != NULL && e->valid)
    {
        return &e->mac;
    }

    return NULL;
}

struct rte_mbuf *arp_alloc_mbuf(u16 opcode)
{
    struct rte_mbuf *m = alloc_mbuf();
    if (unlikely(m == NULL))
    {
        printf("arp_mbuf_alloc alloc mbuf failed!\n");
        return NULL;
    }

    rte_pktmbuf_append(m, ARP_HDR_LEN);

#define IPV4_ADDR_LEN 4
    // add arp header
    struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);
    arp_hdr->arp_hardware = fnp_swap16(RTE_ARP_HRD_ETHER);   // 硬件类型：1 以太网
    arp_hdr->arp_protocol = fnp_swap16(RTE_ETHER_TYPE_IPV4); // 协议类型：0x0800 IP地址
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;                  // 硬件地址长度：6
    arp_hdr->arp_plen = IPV4_ADDR_LEN;                       // 协议地址长度：4
    arp_hdr->arp_opcode = fnp_swap16(opcode);                // OP

    return m;
}

void arp_send_request(fnp_iface_t *iface, u32 tip)
{
    struct rte_mbuf *mbuf = arp_alloc_mbuf(RTE_ARP_OP_REQUEST);
    mbuf->port = iface->id;

    struct rte_arp_hdr *arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_arp_ipv4 *arp_data = &arpHdr->arp_data;

    // sender
    rte_ether_addr_copy(&iface->mac, &arp_data->arp_sha);
    arp_data->arp_sip = iface->ip;

    // target
    memset(&arp_data->arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp_data->arp_tip = tip;

    ether_send_mbuf(iface, mbuf, &broadcast, RTE_ETHER_TYPE_ARP);
}

static void arp_send_reply(fnp_iface_t *iface, struct rte_arp_hdr *req)
{
    struct rte_mbuf *mbuf = arp_alloc_mbuf(RTE_ARP_OP_REPLY);
    mbuf->port = iface->id;

    struct rte_arp_hdr *arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_arp_ipv4 *arp_data = &arpHdr->arp_data;

    // sender
    rte_ether_addr_copy(&iface->mac, &arp_data->arp_sha);
    arp_data->arp_sip = iface->ip;

    // target
    struct rte_ether_addr *tha = &req->arp_data.arp_sha;
    rte_ether_addr_copy(tha, &arp_data->arp_tha);
    arp_data->arp_tip = req->arp_data.arp_sip;

    ether_send_mbuf(iface, mbuf, &arp_data->arp_tha, RTE_ETHER_TYPE_ARP);
}

void arp_recv_mbuf(fnp_iface_t *iface, struct rte_mbuf *m)
{
    struct rte_arp_hdr *arpHdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);

    u32 src_ip = arpHdr->arp_data.arp_sip;
    u32 tip = arpHdr->arp_data.arp_tip;
    // char *ipstr1 = ipv4_ntos(src_ip);
    // char *ipstr2 = ipv4_ntos(tip);
    // FNP_INFO("recv arp from %s for %s\n", ipstr1, ipstr2);
    // rte_free(ipstr1);
    // rte_free(ipstr2);
    if (iface->ip == tip)
    {
        arp_insert_entry(iface, src_ip, &arpHdr->arp_data.arp_sha);
        switch (fnp_swap16(arpHdr->arp_opcode))
        {
        case RTE_ARP_OP_REQUEST:
        {
            arp_send_reply(iface, arpHdr);
            break;
        }
        case RTE_ARP_OP_REPLY:
        {
            break;
        }
        }
    }

    free_mbuf(m);
}

void arp_pend_mbuf(fnp_iface_t *iface, struct rte_mbuf *m, u32 next_ip)
{
    arp_entry_t *e = arp_lookup(next_ip);
    if (likely(e != NULL && e->valid))
    { // 找到arp表项
        ether_send_mbuf(iface, m, &e->mac, RTE_ETHER_TYPE_IPV4);
        return;
    }

    e = arp_insert_entry(NULL, next_ip, NULL); // 此时是无效的
    fnp_pring_enqueue(e->pending, m);
    arp_send_request(iface, next_ip);
}

void arp_update_entry()
{
    u32 next = 0;
    u64 cur_tsc = rte_rdtsc();
    u64 hz = rte_get_tsc_hz();
    u32 *key = NULL;
    arp_entry_t *e = NULL;
    struct rte_mbuf *m = NULL;
    while (hash_iterate(fnp.arpTbl, &key, &e, &next))
    {
        if (e->valid)
        {
            while (fnp_pring_dequeue(e->pending, &m))
            {
                ether_send_mbuf(e->iface, m, &e->mac, RTE_ETHER_TYPE_IPV4);
            }

            // if(cur_tsc - e->tsc > 20 * hz) {
            //     arp_del_entry(e);
            // }
        }

        // arp_send_request(0, e->ip);
    }
}
