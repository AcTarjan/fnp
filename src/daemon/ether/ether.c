#include "fnp_iface.h"
#include "fnp_context.h"
#include "fnp_worker.h"
#include "../../common/fnp_pring.h"
#include "arp.h"
#include "ipv4.h"

void ether_recv_mbuf(struct rte_mbuf* m)
{
    struct rte_ether_hdr* hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);

    u16 type = rte_cpu_to_be_16(hdr->ether_type);
    switch (type)
    {
    case RTE_ETHER_TYPE_IPV4:
        {
            ipv4_recv_mbuf(m);
            break;
        }
    case RTE_ETHER_TYPE_ARP:
        {
            arp_recv_mbuf(m);
            break;
        }
    default:
        {
            // FNP_WARN("unknown ether type: %x\n",
            free_mbuf(m);
        }
    }
}

void ether_send_mbuf(struct rte_mbuf* m, struct rte_ether_addr* dmac, u16 type)
{
    struct rte_ether_hdr* hdr = (struct rte_ether_hdr*)rte_pktmbuf_prepend(m, RTE_ETHER_HDR_LEN);

    struct rte_ether_addr* src_mac = get_port_mac(m->port);
    rte_ether_addr_copy(src_mac, &hdr->src_addr);
    rte_ether_addr_copy(dmac, &hdr->dst_addr);
    hdr->ether_type = fnp_swap16(type);
    m->l2_len = RTE_ETHER_HDR_LEN;

    fnp_worker_t* worker = get_local_worker();
    if (!fnp_pring_enqueue(worker->tx_ring, m))
    {
        FNP_WARN("ether_send_mbuf failed!\n");
        free_mbuf(m);
    }
}
