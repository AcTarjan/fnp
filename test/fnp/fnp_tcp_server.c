#include <unistd.h>

#include "fnp.h"

char* http_resp = "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 22\r\n"
    "\r\n"
    "Hello, World From FNP!\r\n";

int save_tcp_cnx(void* arg)
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
    return FNP_OK;
}


int tcp_cnx_cps(void* arg)
{
    fsocket_t* socket = arg;
    while (1)
    {
        fnp_mbuf_t* mbuf = fnp_recv(socket);
        if (mbuf == NULL)
        {
            break;
        }

        fnp_free_mbuf(mbuf);
        fnp_mbuf_t* send_mbuf = fnp_alloc_mbuf(socket);
        if (send_mbuf == NULL)
        {
            printf("fail to malloc mbuf\n");
            break;
        }

        u8* data = fnp_mbuf_data(send_mbuf);
        int len = strlen(http_resp);
        fnp_memcpy(data, http_resp, len);
        fnp_mbuf_append_data(send_mbuf, len);

        if (fnp_send(socket, send_mbuf) != FNP_OK)
        {
            printf("fail to send mbuf\n");
            break;
        }
    }

    fnp_close(socket);
    return FNP_OK;
}

int worker_accept_conn_loop(void* arg)
{
    fsocket_t* socket = (fsocket_t*)arg;
    printf("worker_accept_conn_loop: %d\n", rte_lcore_id());
    fnp_rate_measure_t meas = {0};
    meas.interval_count = 10000;
    // meas.file = fopen("fnp_tcp_cps", "w"); // 文件不存在会自动创建
    // if (meas.file == NULL)
    // {
    //     printf("无法打开文件\n");
    //     return 1;
    // }

    u64 count = 0;
    while (1)
    {
        fsocket_t* cnx = fnp_accept(socket);
        if (cnx == NULL)
        {
            printf("accept failed\n");
            break;
        }

        fnp_mbuf_t* mbuf = fnp_recv(cnx);
        if (unlikely(mbuf == NULL))
            continue;
        fnp_free_mbuf(mbuf);
        fnp_update_rate_measure(&meas, 1);
        count++;
        if (count % 10000 == 0)
        {
            printf("%llu\n", count);
        }
        // fnp_close(cnx);
        // pthread_t id;
        // pthread_create(&id, NULL, save_tcp_cnx, cnx);
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

    fsockaddr_t local;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 16666);
    fsocket_t* socket = fnp_create_socket(fnp_protocol_tcp, &local, NULL, NULL);
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
