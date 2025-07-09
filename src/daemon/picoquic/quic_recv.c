#include "quic.h"
#include "picoquic_internal.h"
#include "quic_packet.h"
#include "fnp_worker.h"
#include "tls_api.h"

// 处理initial packet
// 判断是否可以创建conn, 如果可以将创建pcnx
// 进行client initial packet的处理
// 继续进行后续的QUIC Packet处理
int quic_server_handle_initial_packet(quic_context_t* quic, quic_cnx_t** pcnx, quic_packet_header* ph)
{
    int ret = 0;
    int packet_len = ph->offset + ph->payload_length;
    /* Create a connection context if the CI is acceptable */
    if (ph->max_data_len < PICOQUIC_ENFORCED_INITIAL_MTU)
    {
        /* Unexpected packet. Reject, drop and log. */
        return PICOQUIC_ERROR_INITIAL_TOO_SHORT;
    }

    if (ph->dest_cnx_id.id_len < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH)
    {
        /* Initial CID too short -- ignore the packet */
        return PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT;
    }

    if (quic->enforce_client_only)
    {
        /* Cannot create a client connection if the context is client only */
        return PICOQUIC_ERROR_SERVER_BUSY;
    }

    if (quic->server_busy || quic->current_number_connections >= quic->tentative_max_number_connections)
    {
        /* Cannot create a client connection now, send immediate close. */
        return PICOQUIC_ERROR_SERVER_BUSY;
    }

    /* This code assumes that *pcnx is always null when screen initial is called. */
    /* Verify the AEAD checkum */
    void* aead_ctx = NULL;
    void* pn_dec_ctx = NULL;

    // 还没创建conn，先获取aead上下文和包号加密上下文。
    ret = picoquic_get_initial_aead_context(quic, ph, 0, 0, &aead_ctx, &pn_dec_ctx);
    if (ret != 0)
    {
        return PICOQUIC_ERROR_MEMORY;
    }

    // 解密包头保护
    quic_packet_t* packet = quic_create_packet(PICOQUIC_MAX_PACKET_SIZE);
    if (packet == NULL)
    {
        return FNP_ERR_MALLOC;
    }
    ph->packet = packet;

    // 主要是为了获取pn64，来解密retry token
    ret = picoquic_remove_header_protection_inner(ph, pn_dec_ctx, 0, 0);
    CHECK_RET(ret);

    if (ph->has_reserved_bit_set)
    {
        /* Cannot have reserved bit set before negotiation completes */
        return FNP_ERR_QUIC_PARSE_PACKET;
    }

    // 没有必要解密
    u8* decrypted_bytes = ph->packet->bytes;
    size_t decrypted_length = picoquic_aead_decrypt_generic(decrypted_bytes + ph->offset,
                                                            ph->data + ph->offset, ph->payload_length,
                                                            ph->pn64, decrypted_bytes, ph->offset, aead_ctx);
    if (decrypted_length >= ph->payload_length)
    {
        return PICOQUIC_ERROR_AEAD_CHECK;
    }
    ph->payload_length = decrypted_length;
    rte_pktmbuf_adj(ph->mbuf, packet_len);
    packet->header_length = ph->offset;
    packet->length = ph->payload_length + ph->offset;

    /* Free the AEAD CTX */
    picoquic_aead_free(aead_ctx);
    /* Free the PN encryption context */
    picoquic_cipher_free(pn_dec_ctx);

    int is_new_token = 0;
    int has_good_token = 0;
    int has_bad_token = 0;
    quic_connection_id_t original_cnxid = {0};
    if (ph->token_length > 0)
    {
        /* If a token is present, verify it. */
        if (picoquic_verify_retry_token(quic, &ph->remote, ph->current_time,
                                        &is_new_token, &original_cnxid, &ph->dest_cnx_id, (uint32_t)ph->pn64,
                                        ph->token_bytes, ph->token_length, 1) == 0)
        {
            has_good_token = 1;
        }
        else
        {
            has_bad_token = 1;
        }
    }

    if (has_bad_token && !is_new_token)
    {
        /* sending a bad retry token is fatal, sending an old new token is not */
        return PICOQUIC_ERROR_INVALID_TOKEN;
    }

    // 没有token，且强制要求token
    if (!has_good_token &&
        (quic->force_check_token || quic->max_half_open_before_retry <= quic->current_number_half_open))
    {
        /* tokens are required before accepting new connections, so ask to queue a retry packet. */

        /* Incoming packet could not be processed, need to send a Retry. */
        if (ph->max_data_len >= PICOQUIC_ENFORCED_INITIAL_MTU)
        {
            if (quic->is_port_blocking_disabled || !quic_check_addr_blocked(&ph->remote))
            {
                picoquic_queue_retry_packet(quic, ph);
            }
        }
        return FNP_ERR_QUIC_TOKEN;
    }

    /* All clear */
    /* Check: what do do with odcid? */
    quic_cnx_t* cnx = picoquic_create_server_cnx(quic, ph->dest_cnx_id, ph->srce_cnx_id, &ph->local,
                                                 &ph->remote, ph->current_time, ph->vn);
    if (cnx == NULL)
    {
        /* Could not allocate the context */
        return PICOQUIC_ERROR_MEMORY;
    }

    if (has_good_token)
    {
        cnx->initial_validated = 1;
        cnx->original_cnxid = original_cnxid;
    }

    // 处理initial packet from client
    // picoquic_incoming_client_initial(&cnx, ph, 1);
    *pcnx = cnx;

    return FNP_OK;
}


/*
 * 对于客户端：若dcid的len为0，则需要通过远端地址来查找cnx，需要通过dcid来查找lcid，
 * 对于服务端：若dcid的len为0，则需要通过远端地址来查找cnx，需要通过dcid或icid来查找lcid
 * lcid的作用：确定path_id, 确定sack_context
 */
quic_cnx_t* quic_find_cnx(quic_context_t* quic, quic_packet_header* ph)
{
    quic_cnx_t* cnx = NULL;
    //需要注意如何通过icid来查找lcid
    if (quic->local_cnxid_length == 0)
    {
        return picoquic_cnx_by_net(quic, &ph->remote);
    }
    if (ph->dest_cnx_id.id_len == quic->local_cnxid_length)
    {
        cnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id, &ph->lcid);
        if (cnx == NULL && (ph->ptype == picoquic_packet_initial || ph->ptype == picoquic_packet_0rtt_protected))
        {
            cnx = picoquic_cnx_by_icid(quic, &ph->dest_cnx_id, &ph->remote);
        }
    }

    return cnx;
}


// 判断数据包是否是无状态重置，并处理无状态数据包
static bool quic_handle_incoming_stateless_reset(quic_context_t* quic, quic_packet_header* ph)
{
    // 判断是否是stateless reset
    if (ph->ptype == picoquic_packet_1rtt_protected &&
        ph->max_data_len >= PICOQUIC_RESET_PACKET_MIN_SIZE)
    {
        // 后16个字节是retry token
        quic_cnx_t* cnx = picoquic_cnx_by_secret(quic,
                                                 ph->data + ph->max_data_len - PICOQUIC_RESET_SECRET_SIZE,
                                                 &ph->remote);
        if (cnx != NULL)
        {
            picoquic_log_app_message(cnx, "Found connection from reset secret");
            picoquic_incoming_stateless_reset(cnx);
            return true;
        }
    }
    return false;
}

/*
 * cnx处理解密后的QUIC数据包
*/
static int quic_cnx_handle_incoming_packet(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = FNP_OK;
    int path_id = 0;
    int path_is_not_allocated = 0;

    // 验证包
    ret = quic_verify_packet(cnx, ph);
    CHECK_RET(ret);

    /* Find the path and if required log the incoming packet */
    if (ph->ptype == picoquic_packet_1rtt_protected)
    {
        /* Find the arrival path and update its state */
        ret = picoquic_find_incoming_path(cnx, ph, &path_id, &path_is_not_allocated);
        if (ret != 0)
        {
            return FNP_ERR_QUIC_FIND_PATH;
        }
    }


    switch (ph->ptype)
    {
    case picoquic_packet_1rtt_protected:
        ret = picoquic_incoming_1rtt(cnx, path_id, ph);
        break;
    case picoquic_packet_initial:
        if (cnx->client_mode)
            ret = picoquic_incoming_server_initial(cnx, ph);
        else
        {
            //只计算一次, 一般initial packet只会是第一个quic packet, 且只包含一次
            cnx->initial_data_received += ph->max_data_len;
            ret = picoquic_incoming_client_initial(&cnx, ph, 1);
        }
        break;
    case picoquic_packet_handshake:
        if (cnx->client_mode)
            ret = picoquic_incoming_server_handshake(cnx, ph);
        else
            ret = picoquic_incoming_client_handshake(cnx, ph);
        break;
    case picoquic_packet_retry:
        ret = picoquic_incoming_retry(cnx, ph);
        break;
    case picoquic_packet_version_negotiation:
        ret = picoquic_incoming_version_negotiation(cnx, ph);
        break;
    case picoquic_packet_0rtt_protected:
        //只计算一次, 一般initial packet只会是第一个quic packet, 且只包含一次
        cnx->initial_data_received += ph->max_data_len;
        ret = picoquic_incoming_0rtt(cnx, ph);
        break;
    default:
        printf("quic_handle_incoming_packet: unexpected packet type %d\n", ph->ptype);
        return PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }
    CHECK_RET(ret);

    if (cnx->cnx_state != picoquic_state_disconnected &&
        ph->ptype != picoquic_packet_version_negotiation)
    {
        cnx->nb_packets_received++;
        cnx->latest_receive_time = ph->current_time;
        /* Mark the sequence number as received */
        ret = picoquic_record_pn_received(cnx, ph->pc, ph->lcid, ph->pn64, ph->receive_time);
        /* Perform ECN accounting */
        picoquic_ecn_accounting(cnx, ph->ecn, ph->pc, ph->lcid);
    }
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, ph->current_time);

    return ret;
}

static int quic_handle_incoming_packet(quic_context_t* quic, struct rte_mbuf* m,
                                       quic_connection_id_t* first_dcid,
                                       u64 receive_time, u64 current_time)
{
    //解析QUIC Packet的头部
    quic_packet_header ph = {0};
    int ret = quic_parse_packet_header(quic, &ph, m, current_time);
    if (ret != FNP_OK)
    {
        return ret;
    }

    // 一个UDP中所有QUIC Packet的DCID必须相同
    if (!picoquic_is_connection_id_null(first_dcid))
    {
        // 两个lcid不相同
        if (picoquic_compare_connection_id(first_dcid, &ph.dest_cnx_id) != 0)
        {
            return PICOQUIC_ERROR_CNXID_SEGMENT;
        }
    }
    else
    {
        *first_dcid = ph.dest_cnx_id;
    }

    // find connection context
    quic_cnx_t* cnx = quic_find_cnx(quic, &ph);
    if (cnx == NULL) //
    {
        // 服务端第一次收到数据包且数据包大小超过1200，进行版本协商
        if (ph.version_index < 0 && ph.max_data_len >= PICOQUIC_ENFORCED_INITIAL_MTU)
        {
            if (quic->is_port_blocking_disabled || !quic_check_addr_blocked(&ph.remote))
            {
                picoquic_prepare_version_negotiation(quic, &ph);
            }
            return FNP_ERR_QUIC_UNSUPPORTED_VERSION;
        }

        // 判断是否是无状态重置
        if (quic_handle_incoming_stateless_reset(quic, &ph))
        {
            return FNP_ERR_QUIC_STATELESS_RESET;
        }

        // 判断是否是client发送的initial packet
        if (ph.ptype == picoquic_packet_initial)
        {
            // 如果成功创建新连接，则继续后续的流程
            ret = quic_server_handle_initial_packet(quic, &cnx, &ph);
            if (ret != FNP_OK)
            {
                return ret;
            }
        }
    }
    else
    {
        //解密数据
        ret = quic_decrypt_packet(cnx, &ph);
        if (ret != FNP_OK)
        {
            if (ret == FNP_ERR_QUIC_AEAD_NOT_READY)
            {
                picoquic_incoming_not_decrypted(cnx, &ph);
            }
            else if (ret == PICOQUIC_ERROR_AEAD_CHECK) //解密失败
            {
                if (ph.ptype == picoquic_packet_handshake &&
                    (cnx->cnx_state == picoquic_state_client_init_sent ||
                        cnx->cnx_state == picoquic_state_client_init_resent))
                {
                    /* Indicates that the server probably sent initial and handshake but initial was lost */
                    if (cnx->pkt_ctx[picoquic_packet_context_initial].pending_first != NULL &&
                        cnx->path[0]->nb_retransmit == 0)
                    {
                        /* Reset the retransmit timer to start retransmission immediately */
                        cnx->path[0]->retransmit_timer = ph.current_time -
                            cnx->pkt_ctx[picoquic_packet_context_initial].pending_first->send_time;
                    }
                }
            }
            else if (ph.ptype == picoquic_packet_1rtt_protected &&
                ph.max_data_len >= PICOQUIC_RESET_PACKET_MIN_SIZE &&
                memcmp(ph.data + ph.max_data_len - PICOQUIC_RESET_SECRET_SIZE,
                       cnx->path[0]->first_tuple->p_remote_cnxid->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0)
            {
                // 解密失败，判断是否是stateless reset
                picoquic_log_app_message(cnx, "Decrypt error, matching reset secret");
                return PICOQUIC_ERROR_STATELESS_RESET;
            }

            return ret;
        }
    }

    return quic_cnx_handle_incoming_packet(cnx, &ph);
}

//处理收到的UDP数据包
void quic_handle_incoming_udp_mbuf(quic_context_t* quic, struct rte_mbuf* m, u64 receive_time, u64 current_time)
{
    // 先确定connID
    int ret = FNP_OK;

    quic_connection_id_t first_dcid = {0};
    while (rte_pktmbuf_data_len(m) > 0)
    {
        ret = quic_handle_incoming_packet(quic, m, &first_dcid, receive_time, current_time);
        if (ret != FNP_OK)
        {
            break;
        }
    }

    free_mbuf(m);
}

// 处理收到的udp数据包的入口函数
void quic_recv_incoming_udp_mbuf(quic_context_t* quic)
{
    fsocket_t* socket = quic->udp_socket;
    struct rte_mbuf* mbufs[16];
    u64 current_time = picoquic_current_time();
    u32 num = fnp_pring_dequeue_burst(socket->rx, mbufs, 16);
    for (int i = 0; i < num; i++)
    {
        // 处理接收到的QUIC数据包
        quic_handle_incoming_udp_mbuf(quic, mbufs[i], current_time, current_time);
    }
}

// 将收到的流数据交付给应用层, picoquic_stream_data_chunk_callback调用
int quic_recv_stream_data(quic_stream_t* stream,
                          uint8_t* bytes, size_t length, int fin)
{
    // 处理按序到达的数据
    struct rte_mbuf* m = alloc_mbuf();
    if (m == NULL)
    {
        printf("quic_recv_stream_data: alloc mbuf failed\n");
        return -1;
    }

    u8* data = rte_pktmbuf_mtod(m, u8*);
    fnp_memcpy(data, bytes, length);
    rte_pktmbuf_append(m, length);

    fsocket_t* socket = &stream->socket;
    if (!fnp_pring_enqueue(socket->rx, m))
    {
        printf("quic_recv_stream_data: enqueue mbuf to stream rx ring failed\n");
        free_mbuf(m);
        return -1;
    }

    return FNP_OK;
}
