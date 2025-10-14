#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include "fnp_common.h"

#include "ff_api.h"
#include "ff_epoll.h"

struct test_info
{
    u64 seq;
    u64 tsc;
    u8 data[1400];
};

#define MAX_EVENTS 512

struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];
FILE* fp;
int epfd;
int sockfd;

#define BUFFER_SIZE 2048
#define REMOTE_IP "192.168.136.88"
#define REMOTE_PORT 18888
#define LOCAL_PORT 16666
fnp_rate_measure_t meas = {0};
char buffer[BUFFER_SIZE] = {0};

struct sockaddr_in server_addr;

int udp_client_echo(void* arg)
{
    /* Wait for events to happen */
    double hz = fnp_get_tsc_hz() / 1000000.0;
    int nevents = ff_epoll_wait(epfd, events, MAX_EVENTS, 0);
    for (int i = 0; i < nevents; ++i)
    {
        if (events[i].events & EPOLLIN)
        {
            struct sockaddr_in cliaddr;
            socklen_t len = sizeof(cliaddr);
            int n = ff_recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                (struct linux_sockaddr*)&cliaddr, &len);
            if (n < 0)
            {
                perror("接收错误");
                continue;
            }
            struct test_info* info = (struct test_info*)buffer;
            u64 tsc = fnp_get_tsc();
            double diff = (double)(tsc - info->tsc) / hz;
            printf("%llu %.2lf\n", info->seq, diff);
            fprintf(fp, "%llu %.2lf\n", info->seq, diff);
            if (info->seq % 1000 == 0)
            {
                fflush(fp);
            }
        }
        else
        {
            printf("unknown event: %8.8X\n", events[i].events);
        }
    }
    return 0;
}


u64 seq = 0;
u64 last_tsc = 0;

int udp_client_send(void* arg)
{
    /* Wait for events to happen */
    u64 tsc = fnp_get_tsc();
    if (tsc - last_tsc > fnp_get_tsc_hz() / 1000000) //
    {
        last_tsc = tsc;
        struct test_info info = {0};
        info.seq = seq++;
        info.tsc = tsc;
        ff_sendto(sockfd, &info, sizeof(info), 0,
                  (struct linux_sockaddr*)&server_addr, sizeof(server_addr));
    }
    return 0;
}


int loop(void* arg)
{
    udp_client_send(arg);

    udp_client_echo(arg);

    return 0;
}

int main()
{
    int argc = 5;
    char* argv[] = {
        "f-stack-udp-client",
        "--conf", "./config.ini",
        "--proc-type=primary",
        "--proc-id=0",
    };
    ff_init(argc, argv);

    sockfd = ff_socket(AF_INET, SOCK_DGRAM, 0);
    printf("sockfd:%d\n", sockfd);
    if (sockfd < 0)
    {
        printf("ff_socket failed\n");
        exit(1);
    }

    int on = 1;
    ff_ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(LOCAL_PORT);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = ff_bind(sockfd, (struct linux_sockaddr*)&my_addr, sizeof(my_addr));
    if (ret < 0)
    {
        printf("ff_bind failed\n");
        exit(1);
    }

    // 设置服务器地址
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(REMOTE_PORT);
    inet_pton(AF_INET, REMOTE_IP, &server_addr.sin_addr);

    // ret = ff_listen(sockfd, MAX_EVENTS);
    // if (ret < 0) {
    //     printf("ff_listen failed\n");
    //     exit(1);
    // }
    fp = fopen("fstack_remote_rtt.txt", "w"); // 文件不存在会自动创建
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        return 1;
    }

    printf("UDP服务器已启动，监听 %d\n", LOCAL_PORT);
    assert((epfd = ff_epoll_create(0)) > 0);
    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);

    meas.interval_count = 50 * 10000; // 每50w计算一次
    ff_run(loop, NULL);
    return 0;
}
