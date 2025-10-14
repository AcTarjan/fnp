#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "fnp_common.h"

#define BUF_SIZE 2000
// #define LISTEN_ADDR "192.168.136.88"
#define LISTEN_ADDR "127.0.0.1"
#define LOCAL_PORT 18888


// 线程参数结构体
typedef struct
{
    int sockfd;
} thread_arg_t;

void* echo_thread(void* arg)
{
    printf("UDP echo服务器已启动，监听地址 %s 端口 %d ...\n", LISTEN_ADDR, LOCAL_PORT);

    int sockfd = (int)arg;
    struct sockaddr_in cliaddr;
    char buffer[BUF_SIZE];
    socklen_t len = sizeof(cliaddr);
    ssize_t n;

    while (1)
    {
        n = recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr*)&cliaddr, &len);
        if (n < 0)
        {
            printf("recvfrom error");
            break;
        }

        n = sendto(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr*)&cliaddr, len);
        if (n < 0)
        {
            printf("sendto error");
        }
    }

    return NULL;
}


// 接收线程函数
void* send_thread(void* arg)
{
    printf("UDP服务器已启动，监听地址 %s 端口 %d ...\n", LISTEN_ADDR, LOCAL_PORT);

    int sockfd = (int)arg;
    struct sockaddr_in cliaddr;
    char buffer[BUF_SIZE];
    socklen_t len = sizeof(cliaddr);
    ssize_t n;
    fnp_rate_measure_t meas = {0};
    meas.interval_count = 50 * 10000; //50w计算一次
    meas.file = fopen("linux_udp_throughput.txt", "w");
    if (meas.file == NULL)
    {
        perror("Failed to open file for writing");
        return NULL;
    }

    while (1)
    {
        n = recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr*)&cliaddr, &len);
        if (n < 0)
        {
            perror("recvfrom error");
            break;
        }

        fnp_update_rate_measure(&meas, n);
    }

    return NULL;
}

int create_socket(const char* addr, int port)
{
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(addr);
    servaddr.sin_port = htons(port);

    if (bind(sockfd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        close(sockfd);
        return 0;
    }

    return sockfd;
}

int main()
{
    int argc = 2;
    char* argv[] = {"fnp_ring", "-l 0,14"};

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        printf("Fail to init EAL\n");
        return -1;
    }
    // 创建套接字
    int sockfd = create_socket(LISTEN_ADDR, LOCAL_PORT);
    if (sockfd == 0)
    {
        return 1;
    }

    ret = fnp_launch_on_lcore(send_thread, (void*)sockfd, -1);
    //ret = fnp_launch_on_lcore(echo_thread, (void*)sockfd, -1);
    if (ret < 0)
    {
        printf("Fail to launch thread on lcore\n");
        close(sockfd);
        return -1;
    }

    rte_eal_mp_wait_lcore();

    close(sockfd);
    return 0;
}
