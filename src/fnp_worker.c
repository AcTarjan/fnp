#include "fnp_ring.h"
#include "fnp_ether.h"
#include "fnp_init.h"
#include "fnp_arp.h"
#include "fnp_tcp_sock.h"
#include "fnp_tcp_out.h"

#include <rte_ethdev.h>
#include <unistd.h>

#define MBUF_BURST_SIZE     64
#define PORT_ID             0
#define RX_QUEUE_ID         0
#define TX_QUEUE_ID         0

#define PREFETCH_OFFSET 3

i32 fnp_process_worker()
{
    u32 lcore_id = rte_lcore_id();
    printf("fnp_process_worker lcore: %u\n", lcore_id);

    struct rte_mbuf* mbufs[MBUF_BURST_SIZE];
    u64 arp_prev_tsc = 0, prev_tsc = 0, cur_tsc;
    u64 hz = rte_get_timer_hz();  //10ms
    fnp_iface_t* iface = fnp_get_iface(0);

    u64 count = 0;

    while(1)
    {
        cur_tsc = rte_rdtsc();

        /**** recv from recv_ring ****/
        i32 nb = fnp_ring_dequeue_bulk(iface->rx_queue, mbufs, MBUF_BURST_SIZE);
        for (i32 i = 0; i < nb; ++i) {
            count++;
            if(count % 10 > 6 ) {       //手动设置丢包
                fnp_free_mbuf(mbufs[i]);
                continue;
            }
            ether_recv_mbuf(mbufs[i], cur_tsc);
        }

        /**** tcp send data ****/
        u8* key;  tcp_sock_t* sk; i32 next = 0;
        while (fnp_hash_iterate(conf.tcpSockTbl, &key, &sk, &next)) {
            if(tcp_state(sk) > TCP_LISTEN)
                tcp_output(sk);
        }

        if (cur_tsc - prev_tsc > hz/100) {    // 10ms
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }

        if (cur_tsc - arp_prev_tsc > hz) {    // 1s
            arp_update_entry();
            arp_prev_tsc = cur_tsc;
        }
    }
}

i32 fnp_rx_tx_worker()
{
    struct rte_mbuf* mbufs[MBUF_BURST_SIZE] = {NULL};
    u32 lcore_id = rte_lcore_id();
    printf("fnp_rx_tx_worker lcore: %u\n", lcore_id);
    fnp_iface_t* iface = fnp_get_iface(0);

    while (1)
    {
        /*** recv from nic ***/
        i32 nb = rte_eth_rx_burst(PORT_ID, RX_QUEUE_ID, mbufs, MBUF_BURST_SIZE);
        if (nb > 0) {
//            printf("rx from nic: %d\n", nb);
            int num = fnp_ring_enqueue_bulk(iface->rx_queue, mbufs, nb);
//            printf("enqueue rx: %d\n", num);
            if(num < nb)
            {
                rte_pktmbuf_free_bulk(&mbufs[num], nb - num);
            }
        }


        /*** send to nic ***/
        nb = fnp_ring_dequeue_bulk(iface->tx_queue, &mbufs, MBUF_BURST_SIZE);
        if(nb > 0)
        {
            int txNum = rte_eth_tx_burst(PORT_ID, TX_QUEUE_ID, mbufs, nb);
//            printf("nb: %d, tx_burst: %d\n", nb, txNum);
            rte_pktmbuf_free_bulk(mbufs, nb);       //不确定要不要释放，在这里释放也能发出去包
//            if(txNum < nb)
//            {
//                rte_pktmbuf_free_bulk(&mbufs[txNum], nb - txNum);
//            }

        }
    }
}
