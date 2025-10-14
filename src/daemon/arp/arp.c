#include "arp.h"
#include "fnp_context.h"
#include "ether.h"

#include <unistd.h>

#include <rte_arp.h>
#include <rte_malloc.h>

#include "fnp_worker.h"

#define ARP_TABLE_SIZE 256

static struct rte_ether_addr broadcast = {
    0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF
};


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

arp_entry_t* arp_insert_entry(u32 ip, struct rte_ether_addr* mac)
{
    arp_entry_t* e = NULL;

    // can't find
    if (unlikely(!hash_lookup(fnp.arpTbl, &ip, (void**)&e)))
    {
        e = fnp_malloc(sizeof(arp_entry_t));
        if (unlikely(e == NULL))
        {
            printf("malloc arp_entry_t failed!\n");
            return NULL;
        }
        e->ip = ip;
    }

    if (mac != NULL)
    {
        e->tsc = rte_rdtsc();
        rte_ether_addr_copy(mac, &e->mac);
    }


    if (likely(!hash_add(fnp.arpTbl, &ip, e)))
    {
        printf("fail to add %u in gArpTable\n", ip);
        fnp_free(e);
        return NULL;
    }

    return e;
}

static void arp_del_entry(arp_entry_t* e)
{
    hash_del(fnp.arpTbl, &e->ip);
    fnp_free(e);
}

arp_entry_t* arp_lookup(u32 ip)
{
    arp_entry_t* e = NULL;

    hash_lookup(fnp.arpTbl, &ip, (void**)&e);

    return e;
}

struct rte_mbuf* arp_alloc_mbuf(u16 opcode)
{
    struct rte_mbuf* m = alloc_mbuf();
    if (unlikely(m == NULL))
    {
        printf("arp_mbuf_alloc alloc mbuf failed!\n");
        return NULL;
    }

    rte_pktmbuf_append(m, ARP_HDR_LEN);

#define IPV4_ADDR_LEN 4
    // add arp header
    struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);
    arp_hdr->arp_hardware = fnp_swap16(RTE_ARP_HRD_ETHER); // 硬件类型：1 以太网
    arp_hdr->arp_protocol = fnp_swap16(RTE_ETHER_TYPE_IPV4); // 协议类型：0x0800 IP地址
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN; // 硬件地址长度：6
    arp_hdr->arp_plen = IPV4_ADDR_LEN; // 协议地址长度：4
    arp_hdr->arp_opcode = fnp_swap16(opcode); // OP

    return m;
}

void arp_send_request(fnp_iface_t* iface, u32 tip)
{
    struct rte_mbuf* mbuf = arp_alloc_mbuf(RTE_ARP_OP_REQUEST);
    if (unlikely(mbuf == NULL))
        return;
    mbuf->port = iface->port;

    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_arp_ipv4* arp_data = &arpHdr->arp_data;

    // sender
    struct rte_ether_addr* src_mac = get_port_mac(iface->port);
    rte_ether_addr_copy(src_mac, &arp_data->arp_sha);
    arp_data->arp_sip = iface->ip;

    // target
    memset(&arp_data->arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp_data->arp_tip = tip;

    ether_send_mbuf(mbuf, &broadcast, RTE_ETHER_TYPE_ARP);
}

static void arp_send_reply(fnp_iface_t* iface, struct rte_arp_hdr* req)
{
    struct rte_mbuf* mbuf = arp_alloc_mbuf(RTE_ARP_OP_REPLY);
    mbuf->port = iface->id;

    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr *);
    struct rte_arp_ipv4* arp_data = &arpHdr->arp_data;

    // sender
    struct rte_ether_addr* src_mac = get_port_mac(iface->port);
    rte_ether_addr_copy(src_mac, &arp_data->arp_sha);
    arp_data->arp_sip = iface->ip;

    // target
    struct rte_ether_addr* tha = &req->arp_data.arp_sha;
    rte_ether_addr_copy(tha, &arp_data->arp_tha);
    arp_data->arp_tip = req->arp_data.arp_sip;

    ether_send_mbuf(mbuf, &arp_data->arp_tha, RTE_ETHER_TYPE_ARP);
}


void arp_recv_mbuf(struct rte_mbuf* m)
{
    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr *);

    u32 sip = arpHdr->arp_data.arp_sip;
    u32 tip = arpHdr->arp_data.arp_tip;

    fnp_iface_t* iface = lookup_iface(tip);
    if (iface == NULL) //不是本机的arp请求
    {
        printf("recv wrong arp\n");
        free_mbuf(m);
        return;
    }

    printf("recv arp in %d for %s\n", fnp_worker_id, iface->name);

    // 注意: 只有worker0会收到arp
    arp_insert_entry(sip, &arpHdr->arp_data.arp_sha);

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

    free_mbuf(m);
}

void arp_handle_local_pending(struct rte_timer* timer, void* arg);

static void start_arp_timer(arp_pend_entry_t* e)
{
    // 启动定时器
    u32 lcore_id = rte_lcore_id();
    u64 hz = rte_get_timer_hz(); // 定时器的频率
    u64 ticks = (1 << e->count) * hz / 100; // n * 10ms
    if (unlikely(rte_timer_reset(&e->timer, ticks, SINGLE, lcore_id,
        arp_handle_local_pending, e) != 0))
    {
        printf("fail to reset timer of arp %u\n", e->ip);
    }
}

void arp_handle_local_pending(struct rte_timer* timer, void* arg)
{
    arp_pend_entry_t* pe = arg;
    arp_entry_t* e = arp_lookup(pe->ip); //检查是否已经确定了arp项
    if (unlikely(e == NULL))
    {
        if (unlikely(pe->count == 5))
        {
            // 放弃发送
            printf("arp request %u timeout\n", pe->ip);
            fnp_list_node_t* node = fnp_list_first(&pe->pending_list);
            while (node != NULL)
            {
                struct rte_mbuf* m = node->value;
                node = node->next;
                free_mbuf(m);
            }
            fnp_free(pe);
            return;
        }
        // 重发arp请求
        pe->count++;
        arp_send_request(pe->iface, pe->ip);
        start_arp_timer(pe);
        return;
    }

    // 发送pending mbuf
    fnp_list_node_t* node = fnp_list_first(&pe->pending_list);
    while (node != NULL)
    {
        struct rte_mbuf* m = node->value;
        node = node->next;
        ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
    }

    // 从hash表中删除
    fnp_worker_t* worker = get_local_worker();
    hash_del(worker->arp_table, &pe->ip);
    // 释放资源
    fnp_free(pe);
}


void arp_pend_mbuf(fnp_iface_t* iface, u32 next_ip, struct rte_mbuf* m)
{
    // 添加到本地pending_mbuf
    fnp_worker_t* worker = get_local_worker();

    arp_pend_entry_t* e = NULL;
    if (!hash_lookup(worker->arp_table, &next_ip, (void**)&e))
    {
        // 创建arp_pend_entry_t
        e = fnp_malloc(sizeof(arp_pend_entry_t));
        if (unlikely(e == NULL))
        {
            free_mbuf(m);
            return;
        }

        e->ip = next_ip;
        e->count = 0;
        e->iface = iface;
        fnp_init_list(&e->pending_list, NULL);
        rte_timer_init(&e->timer);

        // 添加worker的arp table中
        hash_add(worker->arp_table, &next_ip, e);
    }

    // 放入pending队列中
    fnp_list_node_t* node = rte_mbuf_to_priv(m);
    fnp_list_insert_head(&e->pending_list, node, m);

    // 发送arp请求, 只有worker0能收到arp reply
    arp_send_request(iface, next_ip);
    start_arp_timer(e);
}

void arp_update_entry()
{
    u32 next = 0;
    u32* key = NULL;
    arp_entry_t* e = NULL;
    while (hash_iterate(fnp.arpTbl, &key, &e, &next))
    {
        if (0)
        {
            // if(cur_tsc - e->tsc > 20 * hz) {
            //     arp_del_entry(e);
            // }
        }

        // arp_send_request(0, e->ip);
    }
}

