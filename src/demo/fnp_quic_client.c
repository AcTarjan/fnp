#include <unistd.h>

#include "fnp.h"


void quic_client_handle_stream(void* arg)
{
    fnp_quic_stream_t* stream = arg;
    printf("start to recv data from quic strean\n");

    while (1)
    {
        fnp_mbuf_t m = fnp_quic_recv_stream_data(stream);
        if (m == NULL)
        {
            printf("stop to receive data from quic stream\n");
            break;
        }

        char* data = (char*)fnp_mbuf_data(m);
        int len = fnp_get_mbuf_len(m);
        printf("recv %d bytes from quic stream: %s\n", len, data);

        fnp_free_mbuf(m);
    }
}

void quic_client_send_data(fnp_quic_cnx_t cnx)
{
    // 创建流, 发送数据
    printf("start to create quic stream and send data\n");
    fnp_quic_stream_t* stream = fnp_quic_create_stream(cnx, false, 0);
    if (stream == NULL)
    {
        printf("Failed to create quic stream\n");
        return;
    }
    printf("create stream successfully\n");

    pthread_t tid;
    pthread_create(&tid, NULL, quic_client_handle_stream, stream);

    for (int i = 0; i < 10; i++)
    {
        fnp_mbuf_t m = fnp_alloc_mbuf(cnx);
        if (m == NULL)
        {
            printf("Failed to allocate mbuf\n");
            return;
        }

        u8* data = fnp_mbuf_data(m);
        int len = sprintf((char*)data, "Hello from fnp quic cleint %d", i);
        fnp_set_mbuf_len(m, len);
        printf("send on stream: %s\n", data);

        bool fin = false;
        if (i == 9)
            fin = true;
        int ret = fnp_quic_send_stream_data(stream, m, fin);
        if (ret < 0)
        {
            printf("Failed to send data on quic stream of %d\n", i);
            fnp_free_mbuf(m);
            return;
        }

        sleep(1);
    }
}


void start_quic_client()
{
    fsockaddr_t local, remote;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 18888);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, "192.168.136.130", 16666);

    fnp_quic_config_t* conf = fnp_get_quic_config();
    conf->sni = "example.com";
    conf->alpn = "fnp";
    conf->ticket_filename = "sample_ticket_store.bin";
    conf->token_store_filename = "sample_token_store.bin";

    fsocket_t* quic = fnp_create_socket(fnp_protocol_quic, &local, NULL, conf);
    if (quic == NULL)
    {
        printf("Failed to create quic socket\n");
        return;
    }

    printf("create quic context success\n");

    fnp_quic_cnx_t cnx = fnp_quic_create_cnx(quic, &remote);
    if (cnx == NULL)
    {
        printf("Failed to create quic cnx\n");
        return;
    }
    printf("create quic cnx success\n");
    sleep(3);


    quic_client_send_data(cnx);

    while (1)
    {
        fnp_quic_stream_t* stream = fnp_quic_accept_stream(cnx);
        pthread_t tid;
        pthread_create(&tid, NULL, quic_client_handle_stream, stream);
    }
}


int main()
{
    if (fnp_init() != 0)
    {
        printf("fnp init failed\n");
        return -1;
    }


    start_quic_client();
}
