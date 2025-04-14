#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define SERVER_PORT 18888
#define BUFFER_SIZE 1460

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("Usage: %s <protocol> <server_ip> <filename> \n", argv[0]);
        printf("  <protocol>: tcp or udp\n");
        return -1;
    }

    const char *protocol = argv[1];
    const char *server_ip = argv[2];
    const char *filename = argv[3];

    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // 创建套接字
    int sock_type = strcmp(protocol, "udp") == 0 ? SOCK_DGRAM : SOCK_STREAM;
    sockfd = socket(AF_INET, sock_type, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        return -1;
    }

    // 设置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        perror("invalid address");
        close(sockfd);
        return -1;
    }

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connection failed");
        close(sockfd);
        return -1;
    }

    // 打开文件
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        perror("file open failed");
        close(sockfd);
        return -1;
    }

    // 发送文件
    size_t total_bytes_sent = 0;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0)
    {
        ssize_t bytes_sent = send(sockfd, buffer, bytes_read, 0);
        if (bytes_sent < 0)
        {
            perror("send failed");
            break;
        }
        total_bytes_sent += bytes_sent;
    }
    printf("Total bytes sent: %zu\n", total_bytes_sent);
    // 关闭文件和套接字
    close(fp);
    close(sockfd);

    printf("File sent successfully.\n");
    return 0;
}
