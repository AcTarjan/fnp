#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int create_socket(int tcp)
{
    if (tcp)
    {
        return socket(AF_INET, SOCK_STREAM, 0);
    }
    else
    {
        return socket(AF_INET, SOCK_DGRAM, 0);
    }
}

void bind_addr(int sock, char *ip, int port)
{
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    if (ip == NULL)
    {
        local_addr.sin_addr.s_addr = INADDR_ANY;
    }
    else
    {
        if (inet_pton(AF_INET, ip, &local_addr.sin_addr) <= 0)
        {
            perror("Invalid address/ Address not supported");
            close(sock);
            return;
        }
    }

    printf("bind to %s:%d\n", ip, port);
    if (bind(sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0)
    {
        perror("bind failed");
        close(sock);
        return;
    }
}

void set_reuseaddr(int sock)
{
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    // 测试, 不使用reuseaddr
    int tsock1 = create_socket(1);
    set_reuseaddr(tsock1);
    bind_addr(tsock1, "192.168.11.88", 8888);

    int tsock2 = create_socket(1);
    set_reuseaddr(tsock2);
    bind_addr(tsock2, NULL, 8888);

    return 0;
}
