#include "../../inc/fnp.h"
#include "fnp_internal.h"
#include "fnp_config.h"
#include "fnp_msg.h"

fnp_quic_config_t* fnp_get_quic_config()
{
    fnp_quic_config_t* conf = fnp_zmalloc(sizeof(fnp_quic_config_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->congestion_algo = congestion_algo_cubic;
    conf->max_nb_connections = 1;
    conf->local_cid_length = 8;
    return conf;
}

// 创建QUIC连接上下文
fsocket_t* fnp_quic_create_cnx(fsocket_t* quic, fsockaddr_t* remote)
{
    fnp_msg_t* msg = fmsg_new(fmsg_type_create_cnx);
    create_quic_cnx_param_t* req = msg->data;

    req->quic = quic;
    fsockaddr_copy(&req->remote, remote);

    // wait for reply
    int ret = fmsg_send_with_reply(&frontend->master_chan, msg);
    if (ret != 0)
    {
        printf("fail to create socket: %d\n", ret);
        return NULL;
    }

    fsocket_t* cnx = msg->ptr;
    fnp_free(msg);

    u64 us = 100 * 1000; // 100ms
    for (int i = 0; i < 5; i++)
    {
        fnp_sleep(us);
        if (cnx->is_ready)
        {
            return cnx; // 连接成功
        }
        else if (cnx->is_closed)
        {
            break;
        }

        us <<= 1;
    }

    fnp_close(cnx);
    return NULL;
}

fsocket_t* fnp_quic_accept_cnx(fsocket_t* quic)
{
    fsocket_t* socket = quic;
    fsocket_t* cnx = NULL;
    while (!fnp_ring_dequeue(socket->pending_cnxs, (void**)&cnx));

    return cnx;
}

fnp_quic_stream_t* fnp_quic_create_stream(fsocket_t* cnx, bool is_unidir, int priority)
{
    fnp_msg_t* msg = fmsg_new(fmsg_type_create_stream);
    create_stream_param_t* req = msg->data;

    req->cnx = cnx;
    req->is_unidir = is_unidir;
    req->priority = priority;

    // wait for reply
    int ret = fmsg_send_with_reply(&frontend->master_chan, msg);
    if (ret != 0)
    {
        printf("fail to create socket: %d\n", ret);
        return NULL;
    }

    fnp_quic_stream_t* stream = msg->ptr;
    fnp_free(msg);

    return stream;
}


fnp_quic_stream_t* fnp_quic_accept_stream(fsocket_t* cnx)
{
    fnp_quic_stream_t* stream;
    while (!fnp_ring_dequeue(cnx->pending_streams, (void**)&stream));

    return stream;
}


static quic_stream_data_t* quic_init_stream_data(struct rte_mbuf* m)
{
    if (m == NULL)
        return NULL;

    quic_stream_data_t* stream_data = rte_mbuf_to_priv(m);
    stream_data->mbuf = m;
    stream_data->bytes = rte_pktmbuf_mtod(m, u8*);
    stream_data->length = rte_pktmbuf_data_len(m);
    return stream_data;
}

int fnp_quic_stream_send(fnp_quic_stream_t* stream, fnp_mbuf_t* m, bool fin)
{
    quic_stream_data_t* stream_data = quic_init_stream_data(m);
    if (stream_data == NULL)
    {
        return -1; // Error initializing stream data
    }

    stream_data->fin = fin;
    if (!fnp_ring_enqueue(stream->tx, (void*)stream_data))
    {
        return -1;
    }

    return FNP_OK;
}

fnp_mbuf_t* fnp_quic_recv_stream_data(fnp_quic_stream_t* stream)
{
    quic_stream_data_t* stream_data;
    while (!stream->receive_fin && !stream->receive_reset)
    {
        // 收到数据
        if (fnp_ring_dequeue(stream->rx, (void**)&stream_data))
        {
            if (stream_data->fin)
            {
                stream->receive_fin = 1;
            }

            if (stream_data->length > 0)
            {
                struct rte_mbuf* mbuf = stream_data->mbuf;
                // 构造mbuf
                int offset = stream_data->bytes - rte_pktmbuf_mtod(mbuf, u8*);
                mbuf->data_off += offset;

                // 填充 mbuf with stream data
                rte_pktmbuf_append(mbuf, stream_data->length);
                return mbuf;
            }
        }
    }

    return NULL;
}

void fnp_quic_stream_request_stop_sending(fnp_quic_stream_t* stream, u64 stop_error)
{
    // 请求对方停止发送数据
    stream->local_stop_error = stop_error;
    stream->request_stop_sending = 1;
}

void fnp_quic_reset_stream(fnp_quic_stream_t* stream, u64 error)
{
    // 本端将立即中止发送数据
    stream->local_error = error;
    stream->request_reset = 1;
}

void fnp_quic_close_stream(fnp_quic_stream_t* stream)
{
    // 对方的单向流, 不需要发送FIN
    if (!stream->is_local && stream->is_unidirectional)
    {
        stream->request_fin = 0;
    }
    else
    {
        stream->request_fin = 1;
    }
    // 本端发送数据完成
    stream->request_close = 1;
}

void fnp_quic_cnx_close(fsocket_t* cnx, u64 error)
{
    // 本端将立即中止发送数据
    // cnx->local_error = error;
    // cnx->request_close = 1;
    //
    // // 关闭连接
    // fsocket_t* socket = (fsocket_t*)cnx;
    // socket->is_connected = 0;
}
