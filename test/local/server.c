#include <unistd.h>

#include "fnp.h"

struct test_info
{
    u64 seq;
    u64 tsc;
    u8 data[1400];
};

int worker_loop_echo_func(void* arg)
{
    printf("worker_loop_echo_func: %d\n", rte_lcore_id());
    fsocket_t* socket = arg;
    printf("start to echo packet from local udp\n");

    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_recv(socket);
        if (mbuf == NULL)
        {
            printf("recv null mbuf, exit\n");
            break;
        }

        //直接发送回去
        if (fnp_send(socket, mbuf) != FNP_OK)
        {
            fnp_free_mbuf(mbuf);
        }
    }
}

int worker_recv_loop_func(void* arg)
{
    printf("worker_recv_loop_func: %d\n", rte_lcore_id());

    printf("start to recv packet from local\n");

    fsocket_t* socket = arg;
    fnp_rate_measure_t meas = {0};
    meas.file = fopen("fnp_local_throughput.txt", "w"); // 文件不存在会自动创建
    if (meas.file == NULL)
    {
        printf("can't create fnp_local_throughput.txt\n");
        return 1;
    }
    meas.interval_count = 500000; //50w计算一次
    u64 count = 0;
    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_recv(socket);
        if (mbuf == NULL)
        {
            break;
        }

        count++;
        fnp_update_rate_measure(&meas, fnp_get_mbuf_len(mbuf));
        fnp_free_mbuf(mbuf);
        if (count == 1000 * 10000) // 1千万包
        {
            break;
        }
    }

    printf("finish to recv packet\n");
    fsync(fileno(meas.file));
    fclose(meas.file);
}

int main(int argc, char** argv)
{
    // lcore8
    int lcores[] = {7};
    int ret = fnp_init(0, lcores, 1);
    if (ret != FNP_OK)
    {
        printf("Failed to initialize FNP: %d\n", ret);
        return ret;
    }

    fsockaddr_t local, remote;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 18888);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, "192.168.136.88", 16666);
    fsocket_t* socket = fnp_create_socket(fnp_protocol_udp, &local, &remote, NULL);
    if (socket == NULL)
    {
        printf("Failed to create udp socket\n");
        return -1;
    }

    ret = fnp_launch_on_lcore(worker_recv_loop_func, socket, -1);
    if (ret != FNP_OK)
    {
        printf("Failed to launch worker loop: %d\n", ret);
        return ret;
    }

    while (1)
    {
        fnp_sleep(1000 * 1000 * 10);
    }
}
