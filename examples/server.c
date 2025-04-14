#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef long long int i64;

#define PORT 18888
#define BUFFER_SIZE 2024

static inline i64 get_timestamp_us()
{
    struct timeval tv;
    if (gettimeofday(&tv, 0) == -1)
    {
        return -1;
    }

    i64 timestamp = (i64)tv.tv_sec * 1000000LL + (i64)tv.tv_usec;
    return timestamp;
}

void compute_rate(i64 size)
{
    static i64 count = 0;
    static i64 last = 0;

    count += size;
    i64 now = get_timestamp_us();
    i64 diff_time = now - last;
    // printf("now: %lld, last: %lld diff: %lld, count: %lld\n",
    //    now, last, diff_time, count);

    // 每1ms计算一次
    if (diff_time > 5000)
    {
        double bw = (double)count / diff_time;
        if (last != 0)
            printf("bandwidth: %.4lf MBps。 diff: %lldus  total: %lldBytes\n",
                   bw, diff_time, count);
        last = now;
        count = 0;
    }
}

void handle_tcp_connection(int socket)
{
    // 打开文件以写入数据
    char buffer[BUFFER_SIZE] = {0};
    i64 count = 0;

    FILE *fp = fopen("./data/server.data", "wb");
    if (fp == NULL)
    {
        perror("Failed to open file");
        close(socket);
        exit(EXIT_FAILURE);
    }
    printf("start to recv data.\n");
    // 读取数据并写入文件
    ssize_t valread;
    while ((valread = read(socket, buffer, BUFFER_SIZE)) > 0)
    {
        count += valread;
        printf("recv %lld bytes.\n", count);
        size_t val = fwrite(buffer, 1, valread, fp);
        if (val < valread)
        {
            perror("Failed to write to file");
            break;
        }
    }
    printf("recv %lld bytes. start to close!!!\n", count);
    // 关闭文件和socket
    fclose(fp);
    close(socket);
}

void start_tcp_server(int fd)
{
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    printf("TCP server listening on port %d\n", PORT);
    // 监听连接请求
    if (listen(fd, 10) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // 接受客户端连接
    while (1)
    {
        int client_fd = accept(fd, (struct sockaddr *)&address, &addrlen);
        if (client_fd < 0)
        {
            perror("accept");
            continue;
        }
        unsigned short port = htons(address.sin_port);
        printf("client connected from %s:%d\n", inet_ntoa(address.sin_addr), port);

        handle_tcp_connection(client_fd);
    }
}

void start_udp_server(int socket)
{
    char buffer[BUFFER_SIZE] = {0};
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    FILE *fp = fopen("./data/server.data", "wb");
    if (fp == NULL)
    {
        perror("Failed to open file");
        close(socket);
        exit(EXIT_FAILURE);
    }
    printf("start to recv data from udp\n");
    i64 mycount = 0;
    while (1)
    {
        ssize_t valread = recvfrom(socket, buffer, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&client_addr, &addr_len);
        if (valread <= 0)
        {
            break;
        }
        compute_rate(valread);

        // size_t val = fwrite(buffer, 1, valread, fp);
        // if (val < valread)
        // {
        //     perror("Failed to write to file");
        //     break;
        // }

        mycount += valread;
        if (mycount == 14164977)
        {
            printf("udp recv total: %lld \n", mycount);
            mycount = 0;
        }
    }

    fclose(fp);
    close(socket);
}

void start_server(int is_udp)
{
    int server_fd;
    struct sockaddr_in address;
    int opt = 0;

    // 创建socket文件描述符
    int sock_type = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    if ((server_fd = socket(AF_INET, sock_type, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 设置socket选项
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 绑定socket到指定地址和端口
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (is_udp)
    {
        printf("UDP server listening on port %d\n", PORT);
        start_udp_server(server_fd);
    }
    else
    {
        start_tcp_server(server_fd);
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <protocol>\n", argv[0]);
        printf("  <protocol>: tcp or udp\n");
        return -1;
    }

    int is_udp = strcmp(argv[1], "udp") == 0;
    start_server(is_udp);

    return 0;
}
