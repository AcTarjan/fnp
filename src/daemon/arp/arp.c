#include "arp.h"
#include "ether.h"
#include "hash.h"

#include <unistd.h>
#include <string.h>

#include <rte_arp.h>
#include <rte_malloc.h>

#include "fnp_worker.h"

#define ARP_TABLE_SIZE 256

static struct rte_ether_addr broadcast = {
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF
};

typedef struct arp_context
{
    rte_hash* arp_tbl;
} arp_context_t;

static arp_context_t arp_context;

static inline void arp_init_key(arp_key_t* key, const fnp_ifaddr_t* ifaddr, u32 ip)
{
    memset(key, 0, sizeof(*key));
    key->ifaddr_id = ifaddr == NULL ? 0 : ifaddr->id;
    key->ip = ip;
}

static int arp_init_context(void)
{
    arp_context.arp_tbl = hash_create("ArpSocketTable", ARP_TABLE_SIZE, sizeof(arp_key_t));
    if (unlikely(arp_context.arp_tbl == NULL))
    {
        printf("alloc arp table error!\n");
        return -1;
    }

    return 0;
}

static arp_entry_t* arp_insert_entry(fnp_ifaddr_t* ifaddr, u32 ip, struct rte_ether_addr* mac)
{
    arp_key_t key;
    arp_entry_t* e = NULL;
    arp_init_key(&key, ifaddr, ip);

    if (unlikely(!hash_lookup(arp_context.arp_tbl, &key, (void**)&e)))
    {
        e = fnp_malloc(sizeof(arp_entry_t));
        if (unlikely(e == NULL))
        {
            printf("malloc arp_entry_t failed!\n");
            return NULL;
        }
        memset(e, 0, sizeof(*e));
        e->key = key;
    }

    if (mac != NULL)
    {
        e->tsc = rte_rdtsc();
        rte_ether_addr_copy(mac, &e->mac);
    }

    if (likely(!hash_add(arp_context.arp_tbl, &e->key, e)))
    {
        printf("fail to add arp entry for ifaddr %u ip %u\n", key.ifaddr_id, ip);
        fnp_free(e);
        return NULL;
    }

    return e;
}

arp_entry_t* arp_lookup(fnp_ifaddr_t* ifaddr, u32 ip)
{
    arp_key_t key;
    arp_entry_t* e = NULL;
    arp_init_key(&key, ifaddr, ip);
    hash_lookup(arp_context.arp_tbl, &key, (void**)&e);
    return e;
}

static struct rte_mbuf* arp_alloc_mbuf(u16 opcode)
{
    struct rte_mbuf* m = alloc_mbuf();
    if (unlikely(m == NULL))
    {
        printf("arp_mbuf_alloc alloc mbuf failed!\n");
        return NULL;
    }

    rte_pktmbuf_append(m, ARP_HDR_LEN);

#define IPV4_ADDR_LEN 4
    struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);
    arp_hdr->arp_hardware = fnp_swap16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = fnp_swap16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_plen = IPV4_ADDR_LEN;
    arp_hdr->arp_opcode = fnp_swap16(opcode);

    return m;
}

void arp_send_request(fnp_ifaddr_t* ifaddr, u32 tip)
{
    if (ifaddr == NULL || ifaddr->dev == NULL)
    {
        return;
    }

    struct rte_mbuf* mbuf = arp_alloc_mbuf(RTE_ARP_OP_REQUEST);
    if (unlikely(mbuf == NULL))
    {
        return;
    }

    mbuf->port = ifaddr->dev->port_id;
    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_arp_ipv4* arp_data = &arpHdr->arp_data;
    const struct rte_ether_addr* src_mac = get_device_mac(ifaddr->dev);
    rte_ether_addr_copy(src_mac, &arp_data->arp_sha);
    arp_data->arp_sip = ifaddr->local_ip_be;
    memset(&arp_data->arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp_data->arp_tip = tip;

    ether_send_mbuf(mbuf, &broadcast, RTE_ETHER_TYPE_ARP);
}

static void arp_send_reply(fnp_ifaddr_t* ifaddr, struct rte_arp_hdr* req)
{
    if (ifaddr == NULL || ifaddr->dev == NULL)
    {
        return;
    }

    struct rte_mbuf* mbuf = arp_alloc_mbuf(RTE_ARP_OP_REPLY);
    if (unlikely(mbuf == NULL))
    {
        return;
    }

    mbuf->port = ifaddr->dev->port_id;
    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_arp_ipv4* arp_data = &arpHdr->arp_data;
    const struct rte_ether_addr* src_mac = get_device_mac(ifaddr->dev);
    rte_ether_addr_copy(src_mac, &arp_data->arp_sha);
    arp_data->arp_sip = ifaddr->local_ip_be;
    rte_ether_addr_copy(&req->arp_data.arp_sha, &arp_data->arp_tha);
    arp_data->arp_tip = req->arp_data.arp_sip;

    ether_send_mbuf(mbuf, &arp_data->arp_tha, RTE_ETHER_TYPE_ARP);
}

static void arp_recv_mbuf(struct rte_mbuf* m)
{
    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);
    u32 sip = arpHdr->arp_data.arp_sip;
    u32 tip = arpHdr->arp_data.arp_tip;
    fnp_ifaddr_t* ifaddr = lookup_ifaddr(tip);
    if (ifaddr == NULL)
    {
        free_mbuf(m);
        return;
    }

    arp_insert_entry(ifaddr, sip, &arpHdr->arp_data.arp_sha);
    switch (fnp_swap16(arpHdr->arp_opcode))
    {
    case RTE_ARP_OP_REQUEST:
        arp_send_reply(ifaddr, arpHdr);
        break;
    case RTE_ARP_OP_REPLY:
        break;
    }

    free_mbuf(m);
}

static void arp_handle_local_pending(struct rte_timer* timer, void* arg);

static void start_arp_timer(arp_pend_entry_t* e)
{
    u32 lcore_id = rte_lcore_id();
    u64 hz = rte_get_timer_hz();
    u64 ticks = (1 << e->count) * hz / 100;
    if (unlikely(rte_timer_reset(&e->timer, ticks, SINGLE, lcore_id, arp_handle_local_pending, e) != 0))
    {
        printf("fail to reset timer of arp %u\n", e->key.ip);
    }
}

static void arp_handle_local_pending(struct rte_timer* timer, void* arg)
{
    (void)timer;
    arp_pend_entry_t* pe = arg;
    arp_entry_t* e = arp_lookup(pe->ifaddr, pe->key.ip);
    if (unlikely(e == NULL))
    {
        if (unlikely(pe->count == 5))
        {
            fnp_list_node_t* node = fnp_list_first(&pe->pending_list);
            while (node != NULL)
            {
                struct rte_mbuf* m = node->value;
                fnp_list_node_t* next = node->next;
                free_mbuf(m);
                fnp_free(node);
                node = next;
            }
            fnp_free(pe);
            return;
        }

        pe->count++;
        arp_send_request(pe->ifaddr, pe->key.ip);
        start_arp_timer(pe);
        return;
    }

    fnp_list_node_t* node = fnp_list_first(&pe->pending_list);
    while (node != NULL)
    {
        struct rte_mbuf* m = node->value;
        fnp_list_node_t* next = node->next;
        ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
        fnp_free(node);
        node = next;
    }

    fnp_worker_t* worker = get_local_worker();
    hash_del(worker->arp_table, &pe->key);
    fnp_free(pe);
}

void arp_pend_mbuf(fnp_ifaddr_t* ifaddr, u32 next_ip, struct rte_mbuf* m)
{
    fnp_worker_t* worker = get_local_worker();
    arp_key_t key;
    arp_pend_entry_t* e = NULL;
    arp_init_key(&key, ifaddr, next_ip);
    if (!hash_lookup(worker->arp_table, &key, (void**)&e))
    {
        e = fnp_malloc(sizeof(arp_pend_entry_t));
        if (unlikely(e == NULL))
        {
            free_mbuf(m);
            return;
        }

        memset(e, 0, sizeof(*e));
        e->ifaddr = ifaddr;
        e->key = key;
        e->count = 0;
        rte_timer_init(&e->timer);
        fnp_init_list(&e->pending_list, NULL);
        hash_add(worker->arp_table, &e->key, e);

        arp_send_request(ifaddr, next_ip);
        start_arp_timer(e);
    }

    fnp_list_node_t* node = fnp_zmalloc(sizeof(*node));
    if (unlikely(node == NULL))
    {
        free_mbuf(m);
        return;
    }

    fnp_list_insert_tail(&e->pending_list, node, m);
}

void arp_update_entry()
{
}

int arp_module_init(void)
{
    int ret = arp_init_context();
    CHECK_RET(ret);

    return ether_register_input(RTE_ETHER_TYPE_ARP, arp_recv_mbuf);
}
