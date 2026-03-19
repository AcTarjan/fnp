#include <unistd.h>

#include "fnp.h"

void quic_cnx_handle_stream(void* arg)
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

        fnp_quic_send_stream_data(stream, m, false);
    }
}

void quic_server_handle_cnx(void* arg)
{
    fnp_quic_cnx_t cnx = arg;
    printf("start to recv data from quic cnx\n");

    while (1)
    {
        fnp_quic_stream_t* stream = fnp_quic_accept_stream(cnx);
        if (stream == NULL)
        {
            printf("stop to receive new quic stream\n");
            break;
        }
        printf("recv a new quic stream\n");
        pthread_t tid;
        pthread_create(&tid, NULL, quic_cnx_handle_stream, stream);
    }
}

void quic_cnx_send_data(fnp_quic_cnx_t cnx)
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


    fnp_mbuf_t m = fnp_alloc_mbuf(cnx);
    if (m == NULL)
    {
        printf("Failed to allocate mbuf\n");
        return;
    }

    u8* data = fnp_mbuf_data(m);
    int len = sprintf((char*)data, "Hello from fnp quic server!");
    fnp_set_mbuf_len(m, len);

    int ret = fnp_quic_send_stream_data(stream, m, true);
    if (ret < 0)
    {
        printf("Failed to send data on quic stream\n");
        fnp_free_mbuf(m);
    }
}


void start_quic_server()
{
    fsockaddr_t local;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 18888);

    fnp_quic_config_t* conf = fnp_get_quic_config();
    conf->cert_filename = fnp_string_duplicate("./cert.crt");
    conf->key_filename = fnp_string_duplicate("./private.key");
    conf->alpn = fnp_string_duplicate("h3");
    conf->qlog_dir = fnp_string_duplicate("./");
    conf->congestion_algo = congestion_algo_cubic;

    printf("start to create quic context\n");
    fsocket_t* quic = fnp_create_socket(fnp_protocol_quic, &local, NULL, conf);
    if (quic == NULL)
    {
        printf("Failed to create quic socket\n");
        return;
    }

    printf("create quic context success\n");

    printf("start to accept quic cnxs\n");
    while (1)
    {
        fnp_quic_cnx_t cnx = fnp_quic_accept_cnx(quic);
        printf("accept a new quic cnx\n");
        quic_cnx_send_data(cnx);
        pthread_t tid;
        pthread_create(&tid, NULL, quic_server_handle_cnx, cnx);
    }
}


int main()
{
    if (fnp_init() != 0)
    {
        printf("fnp init failed\n");
        return -1;
    }


    start_quic_server();
}
