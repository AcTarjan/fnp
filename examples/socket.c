#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int create_socket(int is_udp)
{
    int sock_type = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    int sockfd = socket(AF_INET, sock_type, 0);
    if (sockfd < 0)
    {
        perror("socket failed");
    }
    return sockfd;
}

void set_sockaddr(struct sockaddr_in *addr, char *ip, int port)
{
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    if (ip == NULL)
    {
        addr->sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        if (inet_pton(AF_INET, ip, &addr->sin_addr) <= 0)
        {
            perror("set_sockaddr");
        }
    }
}

void set_sockopt(int sockfd)
{
    int opt = 1; // 必须设置为1, 表示开启
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("set SO_REUSEADDR");
    }

    // 开启 SO_REUSEPORT 选项
    // opt = 1; // 必须设置为1, 表示开启
    // if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    // {
    //     perror("set SO_REUSEPORT");
    // }
}

void bind_socket(int sockfd, char *ip, int port)
{
    struct sockaddr_in addr;
    set_sockaddr(&addr, ip, port);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind failed");
    }
}

void connect_socket(int sockfd, char *ip, int port)
{
    struct sockaddr_in addr;
    set_sockaddr(&addr, ip, port);
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect failed");
    }
}