#include "fnp_arp.h"
#include "fnp_init.h"
#include "fnp_ether.h"

#include <unistd.h>

#include <rte_arp.h>
#include <rte_malloc.h>

struct rte_ether_addr broadcast = {0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF};

typedef struct arp_entry_t
{
    fnp_ring_t* pending;
    u64 tsc;
    u32 ip;            //网络序，大端
    struct rte_ether_addr mac;
    u16 valid;
} arp_entry_t;



static arp_entry_t* arp_insert_entry(u32 ip, struct rte_ether_addr *mac)
{
    arp_entry_t* e = NULL;

    //can't find
    if(unlikely(fnp_lookup_hash(conf.arpTbl, &ip, &e) == 0))
    {
        e = fnp_malloc(sizeof(arp_entry_t));
        if (unlikely(e == NULL))
        {
            printf("malloc arp_entry_t failed!\n");
            return NULL;
        }

        e->pending = fnp_alloc_ring(8 * 128);
        if (unlikely(e == NULL))
        {
            printf("malloc arp pending failed!\n");
            fnp_free(e);
            return NULL;
        }
    }

    e->ip = ip;
    e->valid = 0;
    if(mac != NULL) {
        e->tsc = rte_rdtsc();
        rte_ether_addr_copy(mac, &e->mac);
        e->valid = 1;
    }

    if (likely(fnp_add_hash(conf.arpTbl, &ip, e) != 0))
    {
        printf("fail to add %u in gArpTable\n", ip);
        fnp_free_ring(e->pending);
        fnp_free(e);
        return NULL;
    }

    return e;
}

static void arp_del_entry(arp_entry_t* e) {
    fnp_del_hash(conf.arpTbl, &e->ip);
    fnp_free_ring(e->pending);
    fnp_free(e);
}

arp_entry_t* arp_lookup(u32 ip)
{
    arp_entry_t* e = NULL;

    fnp_lookup_hash(conf.arpTbl, &ip, &e);

    return e;
}

struct rte_mbuf* arp_alloc_mbuf(u16 opcode)
{
    struct rte_mbuf* mbuf = fnp_alloc_mbuf();
    if(unlikely(mbuf == NULL))
    {
        printf("arp_mbuf_alloc alloc mbuf failed!\n");
        return NULL;
    }

    mbuf->pkt_len = 28;
    mbuf->data_len = 28;

    // add arp header
    struct rte_arp_hdr* arp_hdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr*);
    arp_hdr->arp_hardware = fnp_swap_16(RTE_ARP_HRD_ETHER);        // 硬件类型：1 以太网
    arp_hdr->arp_protocol = fnp_swap_16(RTE_ETHER_TYPE_IPV4);      // 协议类型：0x0800 IP地址
    arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;                             // 硬件地址长度：6
    arp_hdr->arp_plen = 4;                                              // 协议地址长度：4
    arp_hdr->arp_opcode = fnp_swap_16(opcode);                     // OP

    return mbuf;
}

static void arp_send_request(u16 iface_id, u32 tip)
{
    fnp_iface_t* iface = fnp_get_iface(iface_id);
    struct rte_mbuf* mbuf = arp_alloc_mbuf(RTE_ARP_OP_REQUEST);
    mbuf->port = iface_id;

    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr*);
    struct rte_arp_ipv4* arp_data = &arpHdr->arp_data;

    //sender
    rte_ether_addr_copy(&iface->mac, &arp_data->arp_sha);
    arp_data->arp_sip = iface->ip;

    //target
    memset(&arp_data->arp_tha, 0, RTE_ETHER_ADDR_LEN);
    arp_data->arp_tip = tip;

    ether_send_mbuf(mbuf, &broadcast, RTE_ETHER_TYPE_ARP);
}

static void arp_send_reply(fnp_iface_t* iface, struct rte_arp_hdr* req)
{
    struct rte_mbuf* mbuf = arp_alloc_mbuf(RTE_ARP_OP_REPLY);
    mbuf->port = iface->id;

    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr*);
    struct rte_arp_ipv4* arp_data = &arpHdr->arp_data;

    //sender
    rte_ether_addr_copy(&iface->mac, &arp_data->arp_sha);
    arp_data->arp_sip = iface->ip;

    //target
    struct rte_ether_addr* tha = &req->arp_data.arp_sha;
    rte_ether_addr_copy(tha, &arp_data->arp_tha);
    arp_data->arp_tip = req->arp_data.arp_sip;

    ether_send_mbuf(mbuf, &arp_data->arp_tha, RTE_ETHER_TYPE_ARP);
}

void arp_recv_mbuf(struct rte_mbuf* m)
{
    fnp_iface_t* iface = fnp_get_iface(m->port);
    struct rte_arp_hdr* arpHdr = rte_pktmbuf_mtod(m, struct rte_arp_hdr*);

    u32 src_ip = arpHdr->arp_data.arp_sip;
//    fnp_print_ipv4(src_ip);
    if(iface->ip == arpHdr->arp_data.arp_tip)
    {
        arp_insert_entry(src_ip, &arpHdr->arp_data.arp_sha);
//        printf("insert ");
        switch(fnp_swap_16(arpHdr->arp_opcode))
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

    rte_pktmbuf_free(m);
}

void arp_send_mbuf(rte_mbuf *m, u32 next_ip)
{
    arp_entry_t* e = arp_lookup(next_ip);
    if(likely(e != NULL && e->valid)) {
        ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
    } else {
        e = arp_insert_entry(next_ip, NULL);     //此时是无效的
        fnp_ring_enqueue(e->pending, m);
        arp_send_request(m->port, next_ip);
    }

}


void arp_update_entry()
{
    u32 next = 0;
    u64 cur_tsc = rte_rdtsc();
    u64 hz = rte_get_tsc_hz();
    u32* key = NULL;
    arp_entry_t* e = NULL;
    rte_mbuf* m = NULL;
    while (fnp_hash_iterate(conf.arpTbl, &key, &e, &next)) {
        if(e->valid) {
            while (fnp_ring_len(e->pending) != 0) {
                fnp_ring_dequeue(e->pending, &m);
                ether_send_mbuf(m, &e->mac, RTE_ETHER_TYPE_IPV4);
            }

            if(cur_tsc - e->tsc > 5 * hz) {
                arp_del_entry(e);
            }
        }

        arp_send_request(0, e->ip);
    }
}

