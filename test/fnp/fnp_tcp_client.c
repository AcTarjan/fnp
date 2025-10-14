#include <unistd.h>

#include "fnp.h"

int worker_handle_tcp_cnx(void* arg)
{
    fsocket_t* socket = arg;
    printf("start to recv packet from a tcp cnx: %s\n", socket->name);
    char filename[128] = {0};
    snprintf(filename, sizeof(filename), "tcp_cnx_%s.txt", socket->name);
    FILE* fp = fopen(filename, "w"); // 文件不存在会自动创建
    if (fp == NULL)
    {
        printf("无法打开文件\n");
        return 1;
    }

    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_recv(socket);
        if (mbuf == NULL)
        {
            break;
        }

        u8* data = fnp_mbuf_data(mbuf);
        i32 len = fnp_get_mbuf_len(mbuf);

        fwrite(data, 1, len, fp);

        fnp_free_mbuf(mbuf);
    }

    fnp_close(socket);

    fclose(fp);
    printf("write all data to file\n");
}

int worker_accept_conn_loop(void* arg)
{
    fsocket_t* socket = (fsocket_t*)arg;
    printf("worker_accept_conn_loop: %d\n", rte_lcore_id());

    while (1)
    {
        fsocket_t* cnx = fnp_accept(socket);
        if (cnx == NULL)
        {
            printf("accept failed\n");
            break;
        }

        pthread_t id;
        pthread_create(&id, NULL, (void* (*)(void*))worker_handle_tcp_cnx, cnx);
    }
    printf("finish to accept!\n");
}

int main(int argc, char** argv)
{
    // lcore8
    int lcores[] = {5, 6};
    int ret = fnp_init(0, lcores, 2);
    if (ret != FNP_OK)
    {
        printf("Failed to initialize FNP: %d\n", ret);
        return ret;
    }

    fsockaddr_t local, remote;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 18888);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, "192.168.136.99", 19999);
    fsocket_t* socket = fnp_create_socket(fnp_protocol_tcp, &local, &remote, NULL);
    if (socket == NULL)
    {
        printf("Failed to create udp socket\n");
        return -1;
    }

    ret = fnp_launch_on_lcore(worker_accept_conn_loop, socket, -1);
    if (ret != FNP_OK)
    {
        printf("Failed to launch send worker loop: %d\n", ret);
        return ret;
    }

    while (1)
    {
        fnp_sleep(1000 * 1000 * 10);
    }
}
