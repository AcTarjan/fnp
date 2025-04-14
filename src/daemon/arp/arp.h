#ifndef FNP_ARP_H
#define FNP_ARP_H

#include "fnp_common.h"
#include "fnp_iface.h"
#include <rte_ether.h>

#define ARP_HDR_LEN 28

int init_arp_layer();

void arp_send_request(fnp_iface_t *iface, u32 tip);

struct rte_ether_addr *arp_get_mac(u32 ip);

void arp_recv_mbuf(fnp_iface_t *iface, struct rte_mbuf *m);

// 不能直接返回mac的指针，调用者接收到的与返回的会不一致，奇怪！
void arp_pend_mbuf(fnp_iface_t *iface, struct rte_mbuf *m, u32 next_ip);

void arp_update_entry();

#endif // FNP_ARP_H
