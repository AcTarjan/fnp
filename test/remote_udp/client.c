#include "fnp.h"

struct test_info
{
    u64 seq;
    u64 tsc;
    u8 data[1400];
};

int tcp_cnx_cps(void* arg)
{
    printf("worker_recv_loop_func: %d\n", rte_lcore_id());

    fsocket_t* socket = arg;

    printf("start to recv packet from local udp server\n");

    u64 hz = fnp_get_tsc_hz();
    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_recv(socket);
        if (mbuf == NULL)
        {
            break;
        }

        struct test_info* info = (struct test_info*)fnp_mbuf_data(mbuf);

        u64 tsc = fnp_get_tsc();
        double rtt = (double)(tsc - info->tsc) * 1000000.0 / (double)hz;
        printf("seq is %lld, rtt is %.2lfus\n", info->seq, rtt);

        fnp_free_mbuf(mbuf);
    }
}

int handle_incoming_packet(void* arg)
{
    fsocket_t* socket = (fsocket_t*)arg;
    printf("worker_send_loop_func: %d\n", rte_lcore_id());

    u64 seq = 0;
    fnp_rate_measure_t meas = {0};
    meas.interval_count = 500000;
    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_alloc_mbuf(socket);
        if (mbuf == NULL)
        {
            printf("fail to alloc mbuf\n");
            fnp_sleep(1000);
            continue;
        }

        struct test_info* info = (struct test_info*)fnp_mbuf_data(mbuf);
        info->seq = seq++;
        info->tsc = fnp_get_tsc();
        fnp_mbuf_append_data(mbuf, sizeof(struct test_info));

        int ret = fnp_send(socket, mbuf);
        if (ret != FNP_OK)
        {
            // printf("Failed to send data: %d\n", ret);
            fnp_free_mbuf(mbuf);
            // fnp_sleep(1000);
            continue;
        }

        // fnp_update_rate_measure(&meas, fnp_get_mbuf_len(mbuf));
        fnp_block(1000);
    }
    printf("finish to send\n");
}

int main(int argc, char** argv)
{
    // lcore8
    int lcores[] = {5, 6};
    int ret = fnp_init(0, lcores, 2);
    if (ret != FNP_OK)
    {
        printf("Failed to initialize FNP: %d\n", ret);
        return ret;
    }

    fsockaddr_t local, remote;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 18888);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, "192.168.136.99", 19999);
    fsocket_t* socket = fnp_create_socket(fnp_protocol_udp, &local, &remote, NULL);
    if (socket == NULL)
    {
        printf("Failed to create udp socket\n");
        return -1;
    }

    ret = fnp_launch_on_lcore(handle_incoming_packet, socket, -1);
    if (ret != FNP_OK)
    {
        printf("Failed to launch send worker loop: %d\n", ret);
        return ret;
    }

    ret = fnp_launch_on_lcore(tcp_cnx_cps, socket, 6);
    if (ret != FNP_OK)
    {
        printf("Failed to launch recv worker loop: %d\n", ret);
        return ret;
    }

    while (1)
    {
        fnp_sleep(1000 * 1000 * 10);
    }
}
