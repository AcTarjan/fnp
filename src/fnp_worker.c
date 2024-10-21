#include "fnp_ether.h"
#include "fnp_init.h"
#include "fnp_arp.h"
#include "tcp.h"

#include <rte_ethdev.h>
#include <unistd.h>

#define MBUF_BURST_SIZE     128
#define PORT_ID             0
#define RX_QUEUE_ID         0
#define TX_QUEUE_ID         0

#define PREFETCH_OFFSET 3
#include "../examples/exp_common.h"
#include "fnp_pring.h"

i32 fnp_process_worker()
{
    u32 lcore_id = rte_lcore_id();
    printf("fnp_process_worker lcore: %u\n", lcore_id);

    struct rte_mbuf* mbufs[MBUF_BURST_SIZE];
    u64 arp_prev_tsc = 0, prev_tsc = 0, cur_tsc;
    u64 hz = rte_get_timer_hz();  //10ms
    fnp_iface_t* iface = fnp_get_iface(0);

    i64 count = 0;

    while(1)
    {
        cur_tsc = rte_rdtsc();

        //尽量保证
        /**** recv from recv_ring ****/
        i32 nb = fnp_pring_dequeue_bulk(iface->rx_queue, mbufs, MBUF_BURST_SIZE);
        for (i32 i = 0; i < nb; ++i) {
            count ++;
            if (count % 50 > 45) {
                rte_pktmbuf_free(mbufs[i]);
                continue;
            }
            ether_recv_mbuf(mbufs[i], cur_tsc);
        }

        /**** tcp send data ****/
        tcp_socket_output();

        if (cur_tsc - prev_tsc > hz/1000) {    // 1ms
            rte_timer_manage();         //触发定时器
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
    i64 count = 0;

    while (1)
    {
        /*** recv from nic ***/
        i32 rxNum = rte_eth_rx_burst(PORT_ID, RX_QUEUE_ID, mbufs, MBUF_BURST_SIZE);
        if (rxNum > 0) {
//            printf("rx from nic: %d\n", rxNum);
            i32 num = fnp_pring_enqueue_bulk(iface->rx_queue, mbufs, rxNum);
            if (num < rxNum) {
                rte_pktmbuf_free_bulk(mbufs + num, rxNum - num);
            }
        }


        /*** send to nic ***/
        i32 txNum = fnp_pring_dequeue_bulk(iface->tx_queue, mbufs, MBUF_BURST_SIZE);
        if (txNum > 0)
        {
            i32 num = rte_eth_tx_burst(PORT_ID, TX_QUEUE_ID, mbufs, txNum);
//            printf("rxNum: %d, tx_burst: %d\n", num);
            rte_pktmbuf_free_bulk(mbufs, txNum);       //不确定要不要释放，在这里释放也能发出去包
//            if(txNum < rxNum)
//            {
//                rte_pktmbuf_free_bulk(&mbufs[txNum], rxNum - txNum);
//            }

        }
    }
}
