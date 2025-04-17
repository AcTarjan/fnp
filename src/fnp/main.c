#include "fnp.h"

void recv_udp_loop()
{
    uint32_t ip = fnp_ipv4_ston("192.168.11.222");
    uint16_t port = fnp_swap16(18888);
    FNP_SOCKET_TYPE socket = fnp_create_socket(IPPROTO_UDP, ip, port, 0);
    if (socket == NULL)
    {
        printf("bind udp failed\n");
        return;
    }

    fnp_rate_measure_t meas = {0};
    i64 count = 0;
    while (1)
    {
        MBUF_TYPE m = fnp_recv(socket);
        char *data = fnp_mbuf_data(m);
        i32 len = fnp_get_mbuf_len(m);
        count += len;
        fnp_compute_rate(&meas, len);
        fnp_free_mbuf(m);
    }
}

void handle_tcp_conn(FNP_SOCKET_TYPE socket)
{
    printf("accept a new tcp conn\n");
    FILE *fp = fopen("./data/recv_tcp.data", "wb");
    fnp_rate_measure_t meas = {0};
    i64 count = 0;
    while (1)
    {
        MBUF_TYPE m = fnp_recv(socket);
        if (m == NULL)
        {
            printf("recv a null mbuf!. maybe FIN\n");
            break;
        }
        u8 *data = fnp_mbuf_data(m);
        i32 len = fnp_get_mbuf_len(m);
        count += len;
        fnp_compute_rate(&meas, len);

        int num = fwrite(data, 1, len, fp);
        if (num < len)
        {
            printf("write file failed!!!!!!!!!!!\n");
            break;
        }
        fnp_free_mbuf(m);
    }

    printf("close this tcp conn, recv %ld\n", count);
    fclose(fp);
    fnp_close(socket);
}

void recv_tcp_loop()
{
    u32 ip = fnp_ipv4_ston("192.168.11.222");
    u16 port = fnp_swap16(18888);
    FNP_SOCKET_TYPE socket = fnp_create_socket(IPPROTO_TCP, ip, port, 0);
    if (socket == NULL)
    {
        printf("create socket failed!!!\n");
        return;
    }

    while (1)
    {
        FNP_SOCKET_TYPE conn = fnp_accept(socket);
        handle_tcp_conn(conn);
    }
}

void send_tcp_loop()
{
    u32 lip = fnp_ipv4_ston("192.168.11.222");
    u16 lport = fnp_swap16(8888);
    FNP_SOCKET_TYPE socket = fnp_create_socket(IPPROTO_TCP, lip, lport, 0);
    if (socket == NULL)
    {
        printf("create socket failed!!!\n");
        return;
    }

    u32 rip = fnp_ipv4_ston("192.168.11.22");
    u16 rport = fnp_swap16(18888);
    int ret = fnp_connect(socket, rip, rport);
    if (ret < 0)
    {
        printf("connect failed!!!\n");
        return;
    }

    printf("connected to server successfully\n");

    FILE *fp = fopen("./data/data-10M.base64", "rb");
    if (fp == NULL)
    {
        printf("open file failed!!!\n");
        return;
    }

    i64 count = 0;
    i32 num = 0;
    while (1)
    {
        MBUF_TYPE mbuf = fnp_alloc_mbuf();
        u8 *data = fnp_mbuf_data(mbuf);
        if ((num = fread(data, 1, 1460, fp)) > 0)
        {
            fnp_set_mbuf_len(mbuf, num);
            count += num;
            num = fnp_send(socket, mbuf);
            continue;
        }
        break;
    }
    printf("send %lld bytes successfully\n", count);
    fclose(fp);
    fnp_close(socket);
}

void send_udp_loop()
{
    u32 lip = fnp_ipv4_ston("192.168.11.222");
    u16 lport = fnp_swap16(8888);

    FNP_SOCKET_TYPE socket = fnp_create_socket(IPPROTO_UDP, lip, lport, 0);
    if (socket == NULL)
    {
        printf("create socket failed!!!\n");
        return;
    }

    u32 rip = fnp_ipv4_ston("192.168.11.22");
    u16 rport = fnp_swap16(18888);
    int ret = fnp_connect(socket, rip, rport);
    if (ret < 0)
    {
        printf("connect failed!!!\n");
        return;
    }

    printf("connected to server successfully\n");
    FILE *fp = fopen("./data/data-1M.base64", "rb");
    if (fp == NULL)
    {
        printf("open file failed!!!\n");
        return;
    }

    i32 num = 0;
    u64 count = 0;
    while (1)
    {
        MBUF_TYPE mbuf = fnp_alloc_mbuf();
        if (mbuf == NULL)
        {
            printf("send udp alloc mbuf failed\n");
            sleep(5);
            continue;
        }

        u8 *data = fnp_mbuf_data(mbuf);
        if ((num = fread(data, 1, 1460, fp)) > 0)
        {
            count += num;
            fnp_set_mbuf_len(mbuf, num);
            num = fnp_send(socket, mbuf);
            continue;
        }
        break;
    }
    printf("send %ld bytes successfully\n", count);
    fnp_close(socket);
    while (1)
    {
        /* code */
    }
}

int main()
{
    if (fnp_init() != 0)
    {
        printf("fnp init failed\n");
        return -1;
    }

    // recv_tcp_loop();
    // send_tcp_loop();
    // recv_udp_loop();
    // send_udp_loop();
    u32 lip = fnp_ipv4_ston("192.168.11.222");
    u16 lport = fnp_swap16(8888);
    picoquic_sample_client(lip, lport, "192.168.11.88", 16666);
}