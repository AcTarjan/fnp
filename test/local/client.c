#include <unistd.h>

#include "fnp.h"

struct test_info
{
    u64 seq;
    u64 tsc;
    u8 data[1400];
};

u64 total = 1000; // 10w
u64 count = 0;

int tcp_cnx_cps(void* arg)
{
    fsocket_t* socket = arg;
    printf("start to recv packet from local udp server: %d\n", rte_lcore_id());

    u64* start_tsc = fnp_malloc(sizeof(u64) * total);
    if (start_tsc == NULL)
    {
        printf("Failed to allocate memory for start_tsc\n");
        return -1;
    }

    u64* end_tsc = fnp_malloc(sizeof(u64) * total);
    if (end_tsc == NULL)
    {
        printf("Failed to allocate memory for end_tsc\n");
        fnp_free(start_tsc);
        return -1;
    }

    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_recv(socket);
        if (mbuf == NULL)
        {
            break;
        }

        struct test_info* info = (struct test_info*)fnp_mbuf_data(mbuf);

        start_tsc[count] = info->tsc;
        end_tsc[count] = fnp_get_tsc();;

        fnp_free_mbuf(mbuf);

        count++;
        if (count == total)
        {
            break;
        }
    }
    printf("recv all packets, start to write to file\n");
    FILE* fp = fopen("fnp_local_rtt.txt", "w"); // 文件不存在会自动创建
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        return 1;
    }

    double hz = fnp_get_tsc_hz() / 1000000.0;
    for (int i = 0; i < total; i++)
    {
        double rtt = (double)(end_tsc[i] - start_tsc[i]) / hz;
        // printf("seq is %lld, rtt is %.3lfus\n", i, rtt);
        fprintf(fp, "%llu %.3lf\n", i, rtt);
    }
    fsync(fileno(fp));
    fclose(fp);
    printf("write all data to file\n");
}

int handle_incoming_packet(void* arg)
{
    fsocket_t* socket = (fsocket_t*)arg;
    printf("worker_send_loop_func: %d\n", rte_lcore_id());

    u64 seq = 0;
    fnp_rate_measure_t meas = {0};
    meas.interval_count = 500000;
    u64 lost_count = 0;
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

        fnp_update_rate_measure(&meas, fnp_get_mbuf_len(mbuf));

        while (fnp_send(socket, mbuf) != FNP_OK)
        {
            // printf("fail to send mbuf\n");
            lost_count++;
            fnp_block(10);
            fnp_free_mbuf(mbuf);
            continue;
        }

        if (seq >= 1000 * 10000)
        {
            break;
        }
        fnp_block(1);
    }
    printf("finish to send! lost is %llu\n", lost_count);
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
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 16666);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, "192.168.136.88", 18888);
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

    // ret = fnp_launch_on_lcore(worker_recv_loop_func, socket, 6);
    // if (ret != FNP_OK)
    // {
    //     printf("Failed to launch recv worker loop: %d\n", ret);
    //     return ret;
    // }

    while (1)
    {
        fnp_sleep(1000 * 1000 * 10);
    }
}
