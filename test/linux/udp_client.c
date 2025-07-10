#include "fnp_common.h"

struct test_info
{
    u64 seq;
    u64 tsc;
    u8 data[1400];
};

int worker_recv_loop_func(void* arg)
{
    printf("worker_recv_loop_func: %d\n", rte_lcore_id());

    int sockfd = (int)arg;

    printf("start to recv packet from local udp server\n");
    char buffer[2000];
    double hz = (double)fnp_get_tsc_hz() / 1000000.0; // convert to microseconds
    while (1)
    {
        size_t n = recv(sockfd, buffer, 2000, 0);
        if (n < 0)
        {
            printf("recvfrom error");
            continue;
        }

        struct test_info* info = (struct test_info*)buffer;
        u64 tsc = fnp_get_tsc();
        double rtt = (double)(tsc - info->tsc) / hz;
        printf("seq is %lld, rtt is %.2lfus\n", info->seq, rtt);
    }
}

int worker_send_loop_func(void* arg)
{
    int sockfd = (int)arg;
    printf("worker_send_loop_func: %d\n", rte_lcore_id());

    u64 seq = 0;
    fnp_rate_measure_t meas = {0};
    meas.interval_count = 500000;
    while (1)
    {
        struct test_info info = {0};
        info.seq = seq++;
        info.tsc = fnp_get_tsc();

        size_t ret = send(sockfd, &info, sizeof(info), 0);
        if (ret < 0)
        {
            printf("send error\n");
            continue;
        }

        // fnp_update_rate_measure(&meas, fnp_get_mbuf_len(mbuf));
        fnp_block(1);
    }
    printf("finish to send\n");
}

int main()
{
    // lcore8
    int argc = 2;
    char* argv[] = {"fnp_ring", "-l 0,11,12"};
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        printf("Fail to init EAL\n");
        return -1;
    }

    // 解析服务器IP和端口
    const char* server_ip = "192.168.136.88";
    int server_port = 18888;

    // 创建UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket创建失败");
        return 1;
    }

    // 设置服务器地址
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("无效的IP地址");
        return 1;
    }

    // 使用connect连接到服务器
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("连接失败");
        return 1;
    }

    printf("已连接到服务器 %s:%d\n", server_ip, server_port);

    ret = fnp_launch_on_lcore(worker_send_loop_func, (void*)sockfd, -1);
    if (ret != 0)
    {
        printf("Failed to launch send worker loop: %d\n", ret);
        return ret;
    }

    ret = fnp_launch_on_lcore(worker_recv_loop_func, (void*)sockfd, 12);
    if (ret != 0)
    {
        printf("Failed to launch recv worker loop: %d\n", ret);
        return ret;
    }

    rte_eal_mp_wait_lcore();
    printf("All worker loops finished\n");
}
