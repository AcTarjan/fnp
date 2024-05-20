#ifndef FNP_ARP_H
#define FNP_ARP_H

#include "fnp_common.h"
#include "fnp_init.h"
#include <rte_ether.h>

#define ARP_HDR_LEN             28

void arp_recv_mbuf(struct rte_mbuf* m);

//不能直接返回mac的指针，调用者接收到的与返回的会不一致，奇怪！
void arp_send_mbuf(rte_mbuf *m, u32 next_ip);

void arp_update_entry();

#endif //FNP_ARP_H
