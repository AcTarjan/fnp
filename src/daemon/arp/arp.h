#ifndef FNP_ARP_H
#define FNP_ARP_H

#include "fnp_common.h"
#include "fnp_list.h"
#include "fnp_iface.h"
#include <rte_ether.h>
#include <rte_timer.h>

#define ARP_HDR_LEN 28

typedef struct arp_entry_t
{
    u64 tsc;
    u32 ip; // 网络序，大端
    struct rte_ether_addr mac;
} arp_entry_t;

typedef struct arp_pend_entry
{
    fnp_iface_t* iface;
    fnp_list_t pending_list; //等待arp的mbuf
    u32 ip;
    u32 count;
    struct rte_timer timer;
} arp_pend_entry_t;

int init_arp_layer();

// 不能直接返回mac的指针，调用者接收到的与返回的会不一致，奇怪！
arp_entry_t* arp_lookup(u32 ip);

void arp_send_request(fnp_iface_t* iface, u32 tip);

void arp_recv_mbuf(struct rte_mbuf* m);

// arp项不存在, worker暂存mbuf, 向worker发送请求
void arp_pend_mbuf(fnp_iface_t* iface, u32 next_ip, struct rte_mbuf* m);

void arp_update_entry();

#endif // FNP_ARP_H
