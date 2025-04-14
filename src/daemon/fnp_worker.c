#include "fnp_iface.h"
#include "ether.h"
#include "arp.h"
#include "fnp_context.h"
#include "fnp_socket.h"
#include "fnp_pring.h"

#include <rte_ethdev.h>
#include <unistd.h>

#define MBUF_BURST_SIZE 64
#define PORT_ID 0
#define RX_QUEUE_ID 0
#define TX_QUEUE_ID 0
#define PREFETCH_OFFSET 3

void recv_data_from_net()
{
    struct rte_mbuf *mbufs[MBUF_BURST_SIZE] = {0};
    i64 count = 0;
    for (i32 id = 0; id < fnp.iface_num; ++id)
    {
        fnp_iface_t *iface = &fnp.ifaces[id];

        /*** recv from nic ***/
        i32 rxNum = rte_eth_rx_burst(id, RX_QUEUE_ID, mbufs, MBUF_BURST_SIZE);
        for (i32 i = 0; i < rxNum; ++i)
        {
            count++;
            if (count % 1000 == 24) // 人为丢包
            {
                free_mbuf(mbufs[i]);
                continue;
            }
            ether_recv_mbuf(iface, mbufs[i]);
        }
    }
}

int fnp_net_worker()
{
    u32 lcore_id = rte_lcore_id();
    u32 socket_id = rte_socket_id();
    printf("fnp_net_worker lcore: %u in %u\n", lcore_id, socket_id);

    struct rte_mbuf *mbufs[MBUF_BURST_SIZE];
    u64 arp_prev_tsc = 0, mem_prev_tsc = 0, prev_tsc = 0, cur_tsc;
    u64 hz = rte_get_timer_hz(); // 10ms

    u64 count = 0;
    while (1)
    {
        cur_tsc = rte_rdtsc();

        // 收到网卡的数据，会改变TCP的状态
        recv_data_from_net();

        // 检查定时器状态
        if (cur_tsc - prev_tsc > hz / 1000)
        {                       // 1ms
            rte_timer_manage(); // 检查定时器，触发重传
            prev_tsc = cur_tsc;
        }

        // 检查mempool, 每2s检查一次
        if (cur_tsc - mem_prev_tsc > hz * 5)
        {
            show_mempool_info();
            mem_prev_tsc = cur_tsc;
        }

        // 放在重传定时器后面，snd_nxt变小后，在该函数下执行重传动作。
        recv_data_from_app();

        // 更新ARP表
        if (cur_tsc - arp_prev_tsc > hz)
        { // 1s
            // arp_update_entry();
            arp_prev_tsc = cur_tsc;
        }

        // 发送数据
    }
}

int fnp_eth_worker()
{
    struct rte_mbuf *mbufs[MBUF_BURST_SIZE] = {NULL};
    u32 lcore_id = rte_lcore_id();
    printf("fnp_eth_worker lcore: %u\n", lcore_id);

    while (1)
    {
        for (i32 id = 0; id < fnp.iface_num; ++id)
        {
            fnp_iface_t *iface = &fnp.ifaces[id];

            /*** send to nic ***/
            i32 txNum = fnp_pring_dequeue_bulk(iface->tx_queue, mbufs, MBUF_BURST_SIZE);
            if (txNum > 0)
            {
                i32 num = rte_eth_tx_burst(id, TX_QUEUE_ID, mbufs, txNum);
                if (num < txNum)
                {
                    printf("txNum: %d, tx_burst: %d\n", txNum, num);
                    rte_pktmbuf_free_bulk(&mbufs[num], txNum - num);
                }
            }
        }
    }
}

int start_fnp_worker()
{
    fnp_config *conf = &fnp.conf;

    // 启动工作线程
    if (rte_eal_remote_launch(fnp_eth_worker, NULL, conf->worker1) != 0)
    {
        printf("launch %d error!\n", conf->worker1);
        return -1;
    }

    if (rte_eal_remote_launch(fnp_net_worker, NULL, conf->worker2) != 0)
    {
        printf("launch %d error!\n", conf->worker2);
        return -1;
    }

    return 0;
}
