#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int sock;
struct sockaddr_in server;
long total_sent_bytes, totalReadBytes = 0;
long total_received_bytes = 0;

// 线程函数
void *receive_and_save(void *arg) {
    FILE *outfile = fopen("client-recv.dat", "wb");
    if (outfile == NULL) {
        printf("Error opening file.\n");
        return NULL;
    }

    char buf[BUFFER_SIZE];
    memset(buf, 0, BUFFER_SIZE);
    int received_bytes, totalWbytes = 0;
    while (1) {
        received_bytes = recv(sock, buf, BUFFER_SIZE, 0);
        if (received_bytes <= 0) {
            printf("finish to recv: %d\n", received_bytes);
            break;
        }
        total_received_bytes += received_bytes;
        int wBytes = fwrite(buf, 1, received_bytes,outfile);
        totalWbytes += wBytes;
//        printf("Total received bytes: %ld %d %d %d\n", total_received_bytes, totalWbytes, received_bytes, wBytes);
    }
    printf("recv %ld bytes\n", total_received_bytes);
    // 关闭文件
    fclose(outfile);
    close(sock);
    return NULL;
}

int main() {
    pthread_t thread_id;

    // 创建TCP套接字
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("Could not create socket");
    }

    server.sin_addr.s_addr = inet_addr("192.168.11.66");
    server.sin_family = AF_INET;
    server.sin_port = htons(18888);

    // 连接到远程服务器
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed. Error");
        return 1;
    }

    // 创建新线程来接收数据并保存到文件
    if (pthread_create(&thread_id, NULL, receive_and_save, NULL) != 0) {
        perror("could not create thread");
        return 1;
    }

    // 打开文件
    FILE *file = fopen("input.dat", "rb");
    if (file == NULL) {
        printf("Error opening file.\n");
        return -1;
    }

    // 读取文件并发送数据
    char buf[BUFFER_SIZE];
    memset(buf, 0, BUFFER_SIZE);
    int sent_bytes, readBytes;
    printf("start to read\n");
    while (1) {
        readBytes = fread(buf, 1, BUFFER_SIZE, file);
        if (readBytes <= 0) {
            printf("finish to read. %d\n", readBytes);
            break;
        }
        totalReadBytes += readBytes;
        sent_bytes = send(sock, buf, readBytes, 0);
        if (sent_bytes <= 0) {
            printf("send failed\n");
            return -1;
        }
        total_sent_bytes += sent_bytes;
        printf("total send bytes: %ld %ld %d %d\n", totalReadBytes, total_sent_bytes, readBytes, sent_bytes);
    }
    // 关闭文件
    printf("read %ld bytes\n", totalReadBytes);
    printf("close file and socket\n");
    fclose(file);

    printf("shutdown to send\n");
    shutdown(sock, SHUT_WR);

    // 等待线程结束
    pthread_join(thread_id, NULL);

    return 0;
}