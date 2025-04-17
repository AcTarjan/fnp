#include "quic.h"

#include "picoquic.h"
#include "picoquic_internal.h"
#include "fnp_common.h"
#include "fnp_socket.h"
#include "fnp_worker.h"

// 实际发送：quic_prepare_stream_and_datagrams
static void quic_stream_handle_socket(quic_stream_t* stream)
{
    quic_stream_data_t* data;
    quic_cnx_t* cnx = stream->cnx;
    while (fnp_pring_dequeue(stream->socket.tx, (void**)&data))
    {
        data->offset = stream->sent_offset;
        stream->sent_offset += data->length;

        cnx->nb_bytes_queued += data->length;
        quic_stream_enqueue_outcoming_data(stream, data);
    }
}

static void quic_cnx_handle_socket(quic_cnx_t* cnx, u64 current_time)
{
    quic_stream_t* stream = cnx->first_output_stream;
    // 接收应用层的流数据
    while (stream != NULL)
    {
        quic_stream_handle_socket(stream);

        stream = stream->next_output_stream;
    }

    // 判断是否有需要处理的流数据
    stream = quic_find_ready_stream(cnx);
    if (stream != NULL)
    {
        // 唤醒cnx
        if (cnx->next_wake_time > current_time)
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
    }

    // 判断是否有应用层的
}

void quic_context_handle_socket(quic_context_t* quic)
{
    // 遍历所有cnx
    uint64_t current_time = picoquic_current_time();
    quic_cnx_t* cnx = quic->cnx_list;
    while (cnx != NULL)
    {
        quic_cnx_handle_socket(cnx, current_time);
        cnx = cnx->next_in_table;
    }
}

// 处理收到的QUIC数据包
// 发送QUIC数据包
extern void quic_recv_incoming_udp_mbuf(quic_context_t* quic);
extern void quic_send_udp_mbuf(quic_context_t* quic);

static void quic_context_handler(quic_context_t* quic)
{
    fsocket_t* socket = fsocket(quic);
    if (socket->request_close)
    {
        free_socket(socket);
        return;
    }

    //处理应用层的数据
    quic_context_handle_socket(quic);

    // 处理接收到的UDP数据包
    quic_recv_incoming_udp_mbuf(quic);

    // 发送QUIC数据包
    quic_send_udp_mbuf(quic);
}

quic_context_t* quic_create_context(fsockaddr_t* local, fnp_quic_config_t* conf)
{
    quic_context_t* quic = fnp_zmalloc(sizeof(quic_context_t));
    if (quic == NULL)
        return NULL;

    fsocket_t* socket = fsocket(quic);
    socket->handler = quic_context_handler;

    uint64_t current_time = picoquic_current_time();

    int ret = quic_init_context(quic, conf, current_time);
    if (ret != FNP_OK)
    {
        printf("Could not init quic context\n");
        fnp_free(quic);
        return NULL;
    }

    // 创建udp socket, 还是在master线程调用的
    fsocket_t* udp_socket = create_socket(fnp_protocol_udp, local, NULL, NULL, -1);
    if (udp_socket == NULL)
    {
        fnp_free(quic);
        return NULL;
    }
    quic->udp_socket = udp_socket;

    return quic;
}

