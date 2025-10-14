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


#define MAX_EVENTS 512

struct epoll_event ev;
struct epoll_event events[MAX_EVENTS];

int epfd;
int sockfd;

#define BUFFER_SIZE 2048
#define IP "192.168.136.88"
#define LOCAL_PORT 18888
#define BUFFER_SIZE 2048
fnp_rate_measure_t meas = {0};
char buffer[BUFFER_SIZE] = {0};

int udp_server_echo(void* arg)
{
    /* Wait for events to happen */

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
            // fnp_update_rate_measure(&meas, n - 1);
            // buffer[n] = '\0';
            // printf("收到数据%d: %s\n", n, buffer);

            // 发送回去
            n = ff_sendto(sockfd, buffer, n, 0,
                          (struct linux_sockaddr*)&cliaddr, len);
            if (n < 0)
            {
                perror("发送错误");
                continue;
            }
        }
        else
        {
            printf("unknown event: %8.8X\n", events[i].events);
        }
    }
}


int udp_server_loop(void* arg)
{
    /* Wait for events to happen */
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
            buffer[n] = '\0';
            printf("收到数据%d: %s\n", n, buffer);
            // fnp_update_rate_measure(&meas, n - 1);
        }
        else
        {
            printf("unknown event: %8.8X\n", events[i].events);
        }
    }
}

int main()
{
    int argc = 5;
    char* argv[] = {
        "f-stack-udp-server",
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

    printf("UDP服务器已启动，监听%d\n", LOCAL_PORT);
    assert((epfd = ff_epoll_create(0)) > 0);
    ev.data.fd = sockfd;
    ev.events = EPOLLIN;
    ff_epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);

    meas.interval_count = 50 * 10000; // 每50w计算一次
    meas.file = fopen("fstack_remote_throughput-1472.txt", "w"); // 文件不存在会自动创建
    if (meas.file == NULL)
    {
        printf("无法打开文件\n");
        return 1;
    }
    ff_run(udp_server_loop, NULL);
    return 0;
}
