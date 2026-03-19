#ifndef FNP_ARP_H
#define FNP_ARP_H

#include "fnp_common.h"
#include "fnp_list.h"
#include "fnp_network.h"
#include <rte_ether.h>
#include <rte_timer.h>

#define ARP_HDR_LEN 28

typedef struct arp_key
{
    u16 ifaddr_id;
    u16 reserved0;
    u32 ip;
} arp_key_t;

typedef struct arp_entry_t
{
    arp_key_t key;
    u64 tsc;
    struct rte_ether_addr mac;
} arp_entry_t;

typedef struct arp_pend_entry
{
    fnp_ifaddr_t* ifaddr;
    fnp_list_t pending_list;
    arp_key_t key;
    u32 count;
    struct rte_timer timer;
} arp_pend_entry_t;

int arp_module_init(void);

arp_entry_t* arp_lookup(fnp_ifaddr_t* ifaddr, u32 ip);

void arp_send_request(fnp_ifaddr_t* ifaddr, u32 tip);

void arp_pend_mbuf(fnp_ifaddr_t* ifaddr, u32 next_ip, struct rte_mbuf* m);

void arp_update_entry(void);

#endif // FNP_ARP_H
