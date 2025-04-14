#include "fnp_iface.h"
#include "fnp_context.h"
#include "fnp_pring.h"
#include "arp.h"
#include "ipv4.h"

void ether_recv_mbuf(fnp_iface_t *iface, struct rte_mbuf *m)
{
    struct rte_ether_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);

    u16 type = rte_cpu_to_be_16(hdr->ether_type);
    switch (type)
    {
    case RTE_ETHER_TYPE_IPV4:
    {
        ipv4_recv_mbuf(iface, m);
        break;
    }
    case RTE_ETHER_TYPE_ARP:
    {
        arp_recv_mbuf(iface, m);
        break;
    }
    default:
    {
        // FNP_WARN("unknown ether type: %x\n", type);
        free_mbuf(m);
    }
    }
}

void ether_send_mbuf(fnp_iface_t *iface, struct rte_mbuf *m, struct rte_ether_addr *dmac, u16 type)
{
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, RTE_ETHER_HDR_LEN);

    rte_ether_addr_copy(&iface->mac, &hdr->src_addr);
    rte_ether_addr_copy(dmac, &hdr->dst_addr);
    hdr->ether_type = fnp_swap16(type);
    m->l2_len = RTE_ETHER_HDR_LEN;

    if (!fnp_pring_enqueue(iface->tx_queue, m))
    {
        FNP_WARN("ether_send_mbuf failed!\n");
        rte_pktmbuf_free(m);
    }
}
