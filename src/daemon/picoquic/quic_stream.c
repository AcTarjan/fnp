#include "fnp_worker.h"
#include "picoquic_internal.h"
#include "fnp_error.h"


/* stream data 管理 */
int64_t picoquic_stream_data_node_compare(void* l, void* r)
{
    /* Offset values are from 0 to 2^62-1, which means we are not worried with rollover */
    quic_stream_data_t* lnode = l;
    quic_stream_data_t* rnode = r;

    return (int64_t)(lnode->offset - rnode->offset);
}

picosplay_node_t* picoquic_stream_data_node_create(void* value)
{
    return &((quic_stream_data_t*)value)->stream_data_node;
}

void* picoquic_stream_data_node_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_quic_stream_data_t, stream_data_node));
}

static void picoquic_stream_data_node_delete(void* tree, picosplay_node_t* node)
{
    quic_stream_data_t* stream_data = (quic_stream_data_t*)picoquic_stream_data_node_value(node);
    if (!stream_data->enqueue_app)
        free_mbuf(stream_data->mbuf);
}

quic_stream_data_t* quic_stream_first_incoming_data(quic_stream_t* stream)
{
    picosplay_node_t* node = picosplay_first(&stream->rx_stream_data_tree);
    return picoquic_stream_data_node_value(node);
}

void quic_stream_enqueue_incoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data)
{
    picosplay_insert(&stream->rx_stream_data_tree, stream_data);
}

void quic_stream_dequeue_incoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data)
{
    picosplay_delete_hint(&stream->rx_stream_data_tree, &stream_data->stream_data_node);
}

quic_stream_data_t* quic_stream_first_outcoming_data(quic_stream_t* stream)
{
    picosplay_node_t* node = picosplay_first(&stream->tx_stream_data_tree);
    return picoquic_stream_data_node_value(node);
}

void quic_stream_enqueue_outcoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data)
{
    picosplay_insert(&stream->tx_stream_data_tree, stream_data);
}

void quic_stream_dequeue_outcoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data)
{
    picosplay_delete_hint(&stream->tx_stream_data_tree, &stream_data->stream_data_node);
}

quic_stream_data_t* quic_stream_data_alloc()
{
    struct rte_mbuf* mbuf = alloc_mbuf();
    if (mbuf == NULL)
        return NULL;

    quic_stream_data_t* stream_data = rte_mbuf_to_priv(mbuf);
    stream_data->mbuf = mbuf;
    stream_data->bytes = rte_pktmbuf_mtod(mbuf, u8*);
    stream_data->length = 0;
    return stream_data;
}

/*
 * offset是stream帧中的数据对于起始数据的偏移量
 * data_len是帧中数据长度
 */
quic_stream_data_t* quic_create_stream_data_from_packet(quic_packet_t* packet, int offset, int data_len)
{
    struct rte_mbuf* m = clone_mbuf(packet->mbuf);
    if (m == NULL)
    {
        return NULL;
    }

    quic_stream_data_t* stream_data = (quic_stream_data_t*)rte_mbuf_to_priv(m);
    stream_data->mbuf = m;

    stream_data->bytes = rte_pktmbuf_mtod_offset(m, u8*, offset);
    stream_data->length = data_len;
    return stream_data;
}


/* Stream splay management */
static int64_t picoquic_stream_node_compare(void* l, void* r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((quic_stream_t*)l)->stream_id - ((quic_stream_t*)r)->stream_id;
}

static picosplay_node_t* picoquic_stream_node_create(void* value)
{
    return &((quic_stream_t*)value)->stream_node;
}

static void* picoquic_stream_node_value(picosplay_node_t* node)
{
    if (node == NULL)
        return NULL;
    return (void*)((char*)node - offsetof(struct st_quic_stream_t, stream_node));
}

void picoquic_clear_stream(quic_stream_t* stream)
{
    // picoquic_stream_queue_node_t* ready = stream->send_queue;
    // picoquic_stream_queue_node_t* next;
    //
    // while ((next = ready) != NULL)
    // {
    //     ready = next->next_stream_data;
    //     if (next->bytes != NULL)
    //     {
    //         free(next->bytes);
    //     }
    //     free(next);
    // }
    // stream->send_queue = NULL;
    if (stream->is_output_stream)
    {
        picoquic_remove_output_stream(stream->cnx, stream);
    }
    picosplay_empty_tree(&stream->tx_stream_data_tree);
    picosplay_empty_tree(&stream->rx_stream_data_tree);
    picoquic_sack_list_free(&stream->sack_list);
}

static void picoquic_stream_node_delete(void* tree, picosplay_node_t* node)
{
    quic_stream_t* stream = picoquic_stream_node_value(node);

    picoquic_clear_stream(stream);

    fnp_free(stream);
}


void quic_init_stream_tree(picosplay_tree_t* stream_tree)
{
    picosplay_init_tree(stream_tree, picoquic_stream_node_compare, picoquic_stream_node_create,
                        picoquic_stream_node_delete, picoquic_stream_node_value);
}

void quic_init_stream_data_tree(picosplay_tree_t* stream_data_tree)
{
    picosplay_init_tree(stream_data_tree,
                        picoquic_stream_data_node_compare,
                        picoquic_stream_data_node_create,
                        picoquic_stream_data_node_delete,
                        picoquic_stream_data_node_value);
}


/* Management of streams */
quic_stream_t* picoquic_first_stream(quic_cnx_t* cnx)
{
    return picoquic_stream_node_value(picosplay_first(&cnx->stream_tree));
}

quic_stream_t* picoquic_last_stream(quic_cnx_t* cnx)
{
    return picoquic_stream_node_value(picosplay_last(&cnx->stream_tree));
}

quic_stream_t* picoquic_next_stream(quic_stream_t* stream)
{
    if (stream == NULL)
        return NULL;
    return picoquic_stream_node_value(picosplay_next(&stream->stream_node));
}

int picoquic_compare_stream_priority(quic_stream_t* stream, quic_stream_t* other)
{
    int ret = 1;
    if (stream->stream_priority < other->stream_priority)
    {
        ret = -1;
    }
    else if (stream->stream_priority == other->stream_priority)
    {
        if (stream->stream_id < other->stream_id)
        {
            ret = -1;
        }
        else if (stream->stream_id == other->stream_id)
        {
            ret = 0;
        }
    }
    return ret;
}

/* This code assumes that the stream is not currently present in the output stream.
 */
void picoquic_insert_output_stream(quic_cnx_t* cnx, quic_stream_t* stream)
{
    if (stream->is_output_stream == 0)
    {
        if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode)
        {
            if (stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id))
                                         ? cnx->max_stream_id_bidir_remote
                                         : cnx->max_stream_id_unidir_remote))
            {
                return;
            }
        }

        if (cnx->last_output_stream == NULL)
        {
            /* insert first stream */
            cnx->last_output_stream = stream;
            cnx->first_output_stream = stream;
        }
        else if (picoquic_compare_stream_priority(stream, cnx->last_output_stream) >= 0)
        {
            /* insert after last stream. Common case for most applications. */
            stream->previous_output_stream = cnx->last_output_stream;
            cnx->last_output_stream->next_output_stream = stream;
            cnx->last_output_stream = stream;
        }
        else
        {
            quic_stream_t* current = cnx->first_output_stream;

            while (current != NULL)
            {
                int cmp = picoquic_compare_stream_priority(stream, current);

                if (cmp < 0)
                {
                    /* insert before the current stream, then break */
                    stream->previous_output_stream = current->previous_output_stream;
                    if (stream->previous_output_stream == NULL)
                    {
                        cnx->first_output_stream = stream;
                    }
                    else
                    {
                        stream->previous_output_stream->next_output_stream = stream;
                    }
                    current->previous_output_stream = stream;
                    stream->next_output_stream = current;
                    break;
                }
                else if (cmp == 0)
                {
                    /* Stream is already there. This is unexpected */
                    break;
                }
                else
                {
                    current = current->next_output_stream;
                }
            }
            if (current == NULL)
            {
                /* insert after last stream */
                stream->previous_output_stream = cnx->last_output_stream;
                cnx->last_output_stream->next_output_stream = stream;
                cnx->last_output_stream = stream;
            }
        }

        stream->is_output_stream = 1;
    }
}

void picoquic_remove_output_stream(quic_cnx_t* cnx, quic_stream_t* stream)
{
    if (stream->is_output_stream)
    {
        stream->is_output_stream = 0;

        if (stream->previous_output_stream == NULL)
        {
            cnx->first_output_stream = stream->next_output_stream;
        }
        else
        {
            stream->previous_output_stream->next_output_stream = stream->next_output_stream;
        }

        if (stream->next_output_stream == NULL)
        {
            cnx->last_output_stream = stream->previous_output_stream;
        }
        else
        {
            stream->next_output_stream->previous_output_stream = stream->previous_output_stream;
        }
        stream->previous_output_stream = NULL;
        stream->next_output_stream = NULL;
    }
}

/* Reorder streams by priorities and rank.
 * A stream is deemed out of order if:
 * - the previous stream in the list has a higher priority, or
 * - the new stream has a lower priority.
 */
void picoquic_reorder_output_stream(quic_cnx_t* cnx, quic_stream_t* stream)
{
    if (stream->is_output_stream)
    {
        if ((stream->previous_output_stream != NULL &&
                picoquic_compare_stream_priority(stream, stream->previous_output_stream) < 0) ||
            (stream->next_output_stream != NULL &&
                picoquic_compare_stream_priority(stream, stream->next_output_stream) > 0))
        {
            picoquic_remove_output_stream(cnx, stream);
            stream->is_output_stream = 0;
            picoquic_insert_output_stream(cnx, stream);
        }
    }
}


quic_stream_t* picoquic_find_stream(quic_cnx_t* cnx, uint64_t stream_id)
{
    quic_stream_t target;
    target.stream_id = stream_id;

    picosplay_node_t* node = picosplay_find(&cnx->stream_tree, (void*)&target);

    return picoquic_stream_node_value(node);
}

void picoquic_add_output_streams(quic_cnx_t* cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir)
{
    uint64_t old_rank = STREAM_RANK_FROM_ID(old_limit);
    uint64_t first_new_id = STREAM_ID_FROM_RANK(old_rank + 1ull, cnx->client_mode, !is_bidir);
    quic_stream_t* stream = picoquic_find_stream(cnx, first_new_id);

    while (stream)
    {
        if (stream->stream_id > old_limit)
        {
            if (stream->stream_id > new_limit)
            {
                break;
            }
            if (IS_LOCAL_STREAM_ID(stream->stream_id, cnx->client_mode) && IS_BIDIR_STREAM_ID(stream->stream_id) ==
                is_bidir)
            {
                picoquic_insert_output_stream(cnx, stream);
            }
        }
        stream = picoquic_next_stream(stream);
    }
}

// 初始化用户接口
static int quic_init_stream_socket(fnp_quic_stream_t* socket, u64 stream_id, bool client_mode, int priority)
{
    socket->stream_id = stream_id;
    socket->is_local = IS_LOCAL_STREAM_ID(stream_id, client_mode);
    socket->priority = priority;
    socket->is_unidirectional = !IS_BIDIR_STREAM_ID(stream_id);
    socket->tx = fnp_pring_create(64, false, false);
    if (socket->tx == NULL)
    {
        return FNP_ERR_CREATE_RING;
    }


    socket->rx = fnp_pring_create(64, false, false);
    if (socket->rx == NULL)
    {
        return FNP_ERR_CREATE_RING;
    }

    return FNP_OK;
}


quic_stream_t* picoquic_create_stream(quic_cnx_t* cnx, uint64_t stream_id)
{
    quic_stream_t* stream = fnp_zmalloc(sizeof(quic_stream_t));
    if (stream == NULL)
    {
        return NULL;
    }

    int ret = quic_init_stream_socket(&stream->socket, stream_id, cnx->client_mode, cnx->quic->default_stream_priority);
    if (ret != FNP_OK)
    {
        fnp_free(stream);
        return NULL;
    }


    stream->stream_id = stream_id;
    stream->cnx = cnx;
    stream->stream_priority = cnx->quic->default_stream_priority;

    picoquic_sack_list_init(&stream->sack_list);

    quic_init_stream_data_tree(&stream->tx_stream_data_tree);
    quic_init_stream_data_tree(&stream->rx_stream_data_tree);

    picosplay_insert(&cnx->stream_tree, stream);
    picoquic_insert_output_stream(cnx, stream);


    if (stream_id >= cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)])
    {
        cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)] = NEXT_STREAM_ID_FOR_TYPE(stream_id);
    }

    return stream;
}


// quic_stream_t* picoquic_create_missing_streams(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote)
// {
//     /* Verify the stream ID control conditions */
//     quic_stream_t* stream = NULL;
//     unsigned int expect_client_stream = cnx->client_mode ^ is_remote;
//
//
//     if (IS_CLIENT_STREAM_ID(stream_id) != expect_client_stream)
//     {
//         /* TODO: not an error if lower than next stream, would be just an old stream. */
//         picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
//     }
//     else if (is_remote && stream_id > (IS_BIDIR_STREAM_ID(stream_id)
//                                            ? cnx->max_stream_id_bidir_local
//                                            : cnx->max_stream_id_unidir_local))
//     {
//         /* Protocol error, stream ID too high */
//         picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
//     }
//     else if (stream_id < cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)])
//     {
//         /* Protocol error, stream already closed */
//         picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_STATE_ERROR, 0);
//     }
//     else
//     {
//         while (stream_id >= cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)])
//         {
//             stream = picoquic_create_stream(cnx, cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]);
//             if (stream == NULL)
//             {
//                 picoquic_log_app_message(cnx, "Create stream %" PRIu64 " returns error 0x%x",
//                                          stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
//                 picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
//                 break;
//             }
//             else if (!IS_BIDIR_STREAM_ID(stream_id))
//             {
//                 if (!IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode))
//                 {
//                 }
//             }
//         }
//     }
//
//     return stream;
// }

void picoquic_delete_stream(quic_cnx_t* cnx, quic_stream_t* stream)
{
    picosplay_delete(&cnx->stream_tree, stream);
}

quic_stream_t* quic_create_remote_stream(quic_cnx_t* cnx, uint64_t stream_id)
{
    // 是否是本地的stream id
    if (IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode))
    {
        /* TODO: not stream, would be just an old stream. */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
        return NULL;
    }

    if (stream_id > (IS_BIDIR_STREAM_ID(stream_id)
                         ? cnx->max_stream_id_bidir_local
                         : cnx->max_stream_id_unidir_local))
    {
        /* Protocol error, stream ID too high */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
        return NULL;
    }

    if (stream_id < cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)])
    {
        /* Protocol error, stream already closed */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_STATE_ERROR, 0);
        return NULL;
    }

    quic_stream_t* stream = picoquic_create_stream(cnx, stream_id);
    if (stream == NULL)
    {
        return NULL;
    }

    // 双向流
    if (IS_BIDIR_STREAM_ID(stream_id))
    {
        stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_remote;
        stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_local;
    }
    else
    {
        stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_uni;
        stream->maxdata_remote = 0;
        /* Mark the stream as already finished in our direction */
        stream->socket.request_fin = 1;
        stream->fin_sent = 1;
    }

    // 接收到对端的一个新的stream
    fsocket_t* socket = &cnx->socket;
    if (!fnp_pring_enqueue(socket->pending_streams, stream))
    {
        printf("fail to enqueue stream %lld to pending streams\n", stream_id);
        return NULL;
    }

    return stream;
}

// 注意多线程安全, stream_id
quic_stream_t* quic_create_local_stream(quic_cnx_t* cnx, bool is_unidir, int priority)
{
    int type = (cnx->client_mode ^ 1) + (is_unidir << 1);

    // stream id必须保证单调递增，但允许不连续
    u64 stream_id = cnx->next_stream_id[type];

    if (is_unidir)
    {
        if (stream_id > cnx->max_stream_id_unidir_remote)
            return NULL;
    }
    else
    {
        if (stream_id > cnx->max_stream_id_bidir_remote)
            return NULL;
    }


    quic_stream_t* stream = picoquic_create_stream(cnx, stream_id);
    if (stream == NULL)
    {
        return NULL;
    }


    if (is_unidir)
    {
        stream->maxdata_local = 0;
        stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
    }
    else
    {
        stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_local;
        stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
    }


    return stream;
}


quic_stream_t* quic_find_or_create_local_stream(quic_cnx_t* cnx, uint64_t stream_id)
{
    quic_stream_t* stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL)
    {
        stream = quic_create_local_stream(cnx, stream_id, cnx->quic->default_stream_priority);
    }

    return stream;
}

quic_stream_t* quic_find_or_create_remote_stream(quic_cnx_t* cnx, uint64_t stream_id)
{
    quic_stream_t* stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL)
    {
        stream = quic_create_remote_stream(cnx, stream_id);
    }

    return stream;
}
