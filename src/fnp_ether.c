#include "fnp_arp.h"
#include "fnp_ipv4.h"

void ether_recv_mbuf(struct rte_mbuf *m, u64 tsc)
{
    struct rte_ether_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
    rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);

    switch (rte_cpu_to_be_16(hdr->ether_type))
    {
        case RTE_ETHER_TYPE_IPV4:
        {
            ipv4_recv_mbuf(m, tsc);
            break ;
        }
        case RTE_ETHER_TYPE_ARP:
        {
            arp_recv_mbuf(m);
            break ;
        }
        default:
            rte_pktmbuf_free(m);
    }
}

u64 txCount = 0;

void ether_send_mbuf(struct rte_mbuf *m, struct rte_ether_addr *dmac, u16 type)
{
    fnp_iface_t* iface = fnp_get_iface(m->port);
    struct rte_ether_hdr* hdr = (struct rte_ether_hdr*)rte_pktmbuf_prepend(m, RTE_ETHER_HDR_LEN);

    rte_ether_addr_copy(&iface->mac, &hdr->src_addr);
    rte_ether_addr_copy(dmac, &hdr->dst_addr);
    hdr->ether_type = fnp_swap_16(type);
    m->l2_len = RTE_ETHER_HDR_LEN;

//    txCount++;
//    if (txCount % 10 > 7) {
//        rte_pktmbuf_free(m);
//        return;
//    }

    if(!fnp_pring_enqueue(iface->tx_queue, m))
    {
        rte_pktmbuf_free(m);
    }
}


