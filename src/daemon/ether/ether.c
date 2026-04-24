#include "ether.h"
#include "fnp_context.h"
#include "fnp_worker.h"
#include "fnp_ring.h"
#include "arp.h"

#define ETHER_INPUT_TABLE_SIZE 65536

static ether_input_func ether_input_table[ETHER_INPUT_TABLE_SIZE];

static void ether_drop_input(struct rte_mbuf *m)
{
    free_mbuf(m);
}

int init_ether_layer(void)
{
    for (u32 i = 0; i < ETHER_INPUT_TABLE_SIZE; ++i)
    {
        ether_input_table[i] = ether_drop_input;
    }

    return FNP_OK;
}

int ether_register_input(u16 ethertype, ether_input_func input)
{
    ether_input_table[ethertype] = input == NULL ? ether_drop_input : input;
    return FNP_OK;
}

void ether_recv_mbuf(struct rte_mbuf *m)
{
    struct rte_ether_hdr *hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    rte_pktmbuf_adj(m, RTE_ETHER_HDR_LEN);

    u16 type = rte_be_to_cpu_16(hdr->ether_type);
    ether_input_table[type](m);
}

void ether_send_mbuf(struct rte_mbuf *m, fnp_device_t *dev, struct rte_ether_addr *dmac, u16 type)
{
    if (unlikely(m == NULL || dev == NULL || dmac == NULL))
    {
        free_mbuf(m);
        return;
    }

    if (unlikely(!is_ethernet_device(dev)))
    {
        free_mbuf(m);
        return;
    }

    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, RTE_ETHER_HDR_LEN);
    if (unlikely(hdr == NULL))
    {
        free_mbuf(m);
        return;
    }

    const struct rte_ether_addr *src_mac = get_device_mac(dev);
    if (unlikely(src_mac == NULL))
    {
        free_mbuf(m);
        return;
    }

    rte_ether_addr_copy(src_mac, &hdr->src_addr);
    rte_ether_addr_copy(dmac, &hdr->dst_addr);
    hdr->ether_type = fnp_swap16(type);
    m->l2_len = RTE_ETHER_HDR_LEN;

    fnp_worker_t *worker = get_local_worker();
    fnp_ring_t *tx_ring = get_device_tx_ring(dev, worker->queue_id);
    if (unlikely(tx_ring == NULL || fnp_ring_enqueue(tx_ring, m) == 0))
    {
        FNP_WARN("ether_send_mbuf failed!\n");
        free_mbuf(m);
    }
}

void ether_device_send(fnp_device_t *dev, struct rte_mbuf *m, const struct rte_ether_addr *dmac)
{
    if (unlikely(m == NULL || dev == NULL || dmac == NULL))
    {
        free_mbuf(m);
        return;
    }

    ether_send_mbuf(m, dev, (struct rte_ether_addr *)dmac, RTE_ETHER_TYPE_IPV4);
}
