#ifndef FNP_ARP_H
#define FNP_ARP_H

#include "fnp_common.h"
#include "fnp_iface.h"
#include <rte_ether.h>

#define ARP_HDR_LEN 28

typedef struct arp_entry_t
{
    u32 ip; // 网络序，大端
    u64 tsc;
    struct rte_ether_addr mac;
    u16 valid;
} arp_entry_t;

typedef struct arp_pend_entry
{
    u64 tsc; //创建时的时间
    int efd;
    u32 ip;
    fnp_pring_t* pending; //等待arp的mbuf
    fnp_iface_t* iface;
} arp_pend_entry_t;

int init_arp_layer();

// 不能直接返回mac的指针，调用者接收到的与返回的会不一致，奇怪！
arp_entry_t* arp_lookup(u32 ip);

void arp_send_request(fnp_iface_t* iface, u32 tip);

struct rte_ether_addr* arp_get_mac(u32 ip);

void arp_recv_mbuf(struct rte_mbuf* m);

// arp项不存在, worker暂存mbuf, 向worker发送请求
void arp_pend_mbuf(fnp_iface_t* iface, u32 next_ip, struct rte_mbuf* m);

// 检查是否收到arp请求,发送pending mbuf
void arp_handle_local_pending();


void arp_update_entry();

#endif // FNP_ARP_H
