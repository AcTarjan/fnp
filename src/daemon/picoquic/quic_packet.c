#include "picoquic_internal.h"
#include "picoquic_binlog.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "quic_packet.h"
#include "fnp_error.h"
#include "fnp_worker.h"
#include "fnp_sockaddr.h"

picoquic_packet_type_enum picoquic_parse_long_packet_type(uint8_t flags, int version_index)
{
    picoquic_packet_type_enum pt = picoquic_packet_error;

    switch (picoquic_supported_versions[version_index].packet_type_version)
    {
    case PICOQUIC_V1_VERSION:
        switch ((flags >> 4) & 3)
        {
        case 0: /* Initial */
            pt = picoquic_packet_initial;
            break;
        case 1: /* 0-RTT Protected */
            pt = picoquic_packet_0rtt_protected;
            break;
        case 2: /* Handshake */
            pt = picoquic_packet_handshake;
            break;
        case 3: /* Retry */
            pt = picoquic_packet_retry;
            break;
        }
        break;
    case PICOQUIC_V2_VERSION:
        /* Initial packets use a packet type field of 0b01. */
        /* 0-RTT packets use a packet type field of 0b10. */
        /* Handshake packets use a packet type field of 0b11. */
        /* Retry packets use a packet type field of 0b00.*/
        switch ((flags >> 4) & 3)
        {
        case 1: /* Initial */
            pt = picoquic_packet_initial;
            break;
        case 2: /* 0-RTT Protected */
            pt = picoquic_packet_0rtt_protected;
            break;
        case 3: /* Handshake */
            pt = picoquic_packet_handshake;
            break;
        case 0: /* Retry */
            pt = picoquic_packet_retry;
            break;
        }
        break;
    default:
        break;
    }
    return pt;
}

// FNP_ERR_PARSE_QUIC_PACKET
// PICOQUIC_ERROR_VERSION_NOT_SUPPORTED
// FNP_ERR_QUIC_FIXED_BIT
// FNP_OK
int quic_parse_long_packet_header(quic_context_t* quic, quic_packet_header* ph)
{
    u8* bytes = ph->data;
    const u8* bytes_start = bytes;
    const u8* bytes_max = bytes + ph->max_data_len;
    uint8_t flags = 0;

    // 解析第一个字节flags
    if ((bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &flags)) == NULL)
    {
        return FNP_ERR_QUIC_PARSE_PACKET;
    }
    // 解析版本号
    if ((bytes = picoquic_frames_uint32_decode(bytes, bytes_max, &ph->vn)) == NULL)
    {
        return FNP_ERR_QUIC_PARSE_PACKET;
    }

    // 解析dst_cnx_id和src_cnx_id
    if ((bytes = picoquic_frames_cid_decode(bytes, bytes_max, &ph->dest_cnx_id)) == NULL ||
        (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &ph->srce_cnx_id)) == NULL)
    {
        return FNP_ERR_QUIC_PARSE_PACKET;
    }
    ph->offset = bytes - bytes_start;

    if (ph->vn != 0)
    {
        ph->version_index = picoquic_get_version_index(ph->vn);
        if (ph->version_index < 0)
        {
            return FNP_OK;
        }
    }
    else
    {
        // 版本号为0表示这是一个版本协商包
        ph->ptype = picoquic_packet_version_negotiation;
        ph->pc = picoquic_packet_context_initial;
        ph->payload_length = (ph->max_data_len > ph->offset) ? ph->max_data_len - ph->offset : 0;
        return FNP_OK;
    }

    int payload_length = 0;
    /* If the version is supported now, the format field in the version table
     * describes the encoding. */
    ph->quic_bit_is_zero = (flags & 0x40) == 0;
    if (!is_potential_quic_packet(flags))
    {
        // Fixed bit没有置1,直接丢弃
        return FNP_ERR_QUIC_FIXED_BIT;
    }

    ph->ptype = picoquic_parse_long_packet_type(flags, ph->version_index);
    switch (ph->ptype) // 确定epoch
    {
    case picoquic_packet_initial: /* Initial */
        {
            /* special case of the initial packets. They contain a retry token between the header
             * and the encrypted payload */
            size_t tok_len = 0;
            bytes = picoquic_frames_varlen_decode(bytes, bytes_max, &tok_len);
            size_t bytes_left = bytes_max - bytes;
            if (bytes_left < tok_len) // 没有足够的token字节
            {
                return FNP_ERR_QUIC_PARSE_PACKET;
            }

            ph->epoch = picoquic_epoch_initial;
            ph->pc = picoquic_packet_context_initial;
            ph->token_length = tok_len;
            ph->token_bytes = bytes;
            bytes += tok_len;
            ph->offset = bytes - bytes_start;
            break;
        }
    case picoquic_packet_0rtt_protected: /* 0-RTT Protected */
        ph->pc = picoquic_packet_context_application;
        ph->epoch = picoquic_epoch_0rtt;
        break;
    case picoquic_packet_handshake: /* Handshake */
        ph->pc = picoquic_packet_context_handshake;
        ph->epoch = picoquic_epoch_handshake;
        break;
    case picoquic_packet_retry: /* Retry */
        ph->pc = picoquic_packet_context_initial;
        ph->epoch = picoquic_epoch_initial;
        break;
    default: /* Not a valid packet type */
        DBG_PRINTF("Packet type is not recognized: v=%08x, p[0]= 0x%02x\n", ph->vn, flags);
        return FNP_ERR_QUIC_WRONG_PACKET_TYPE;
    }

    // 重传数据包没有length字段
    if (ph->ptype != picoquic_packet_retry)
    {
        bytes = picoquic_frames_varlen_decode(bytes, bytes_max, &payload_length);
        int bytes_left = (bytes_max > bytes) ? bytes_max - bytes : 0;
        if (bytes_left < payload_length)
        {
            return FNP_ERR_QUIC_PARSE_PACKET;
        }
    }
    else
    {
        // 剩余的字节数就是token
        payload_length = ph->max_data_len - ph->offset;
        if (payload_length <= 0)
        {
            // 没有retry token
            return FNP_ERR_QUIC_PARSE_PACKET;
        }
    }

    ph->payload_length = payload_length;
    ph->offset = bytes - bytes_start;

    return FNP_OK;
}

// 解析短包的头部,即1-RTT数据包
// 暂时不考虑服务端
static int quic_parse_short_packet_header(quic_context_t* quic, quic_packet_header* ph) // 表示是否是接收到的包
{
    u8* data = ph->data;
    int local_cnxid_len = quic->local_cnxid_length;
    if (ph->max_data_len < 1 + local_cnxid_len) // 1字节表示flags
    {
        return FNP_ERR_QUIC_PARSE_PACKET;
    }

    /* 解析DCID */
    ph->offset = 1 + picoquic_parse_connection_id(data + 1, local_cnxid_len, &ph->dest_cnx_id);

    ph->quic_bit_is_zero = (data[0] & 0x40) == 0;
    if (!is_potential_quic_packet(data[0]))
    {
        // Fixed bit没有置1,直接丢弃
        return FNP_ERR_QUIC_FIXED_BIT;
    }

    ph->pc = picoquic_packet_context_application;
    ph->epoch = picoquic_epoch_1rtt;
    ph->ptype = picoquic_packet_1rtt_protected;
    ph->has_spin_bit = 1;
    ph->spin = (data[0] >> 5) & 1;
    ph->pn = 0;
    ph->pnmask = 0;
    ph->key_phase = ((data[0] >> 2) & 1); /* Initialize here so that simple tests with unencrypted headers can work */

    ph->payload_length = ph->max_data_len - ph->offset;

    return FNP_OK;
}

// 解析包的头部
int quic_parse_packet_header(quic_context_t* quic, quic_packet_header* ph, struct rte_mbuf* m, u64 current_time)
{
    int ret = FNP_OK;

    ph->mbuf = m;
    ph->data = rte_pktmbuf_mtod(m, u8 *);
    ph->max_data_len = rte_pktmbuf_data_len(m);
    ph->current_time = current_time;

    fmbuf_info_t* info = get_fmbuf_info(m);
    fsockaddr_copy(&ph->local, &info->local);
    fsockaddr_copy(&ph->remote, &info->remote);

    if (is_long_header_packet(ph->data[0]))
    {
        ret = quic_parse_long_packet_header(quic, ph);
    }
    else
    {
        ret = quic_parse_short_packet_header(quic, ph);
    }

    return ret;
}

/* The packet number logic */
uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn)
{
    uint64_t expected = highest + 1;
    uint64_t not_mask_plus_one = (~mask) + 1;
    uint64_t pn64 = (expected & mask) | pn;

    if (pn64 < expected)
    {
        uint64_t delta1 = expected - pn64;
        uint64_t delta2 = not_mask_plus_one - delta1;
        if (delta2 < delta1)
        {
            pn64 += not_mask_plus_one;
        }
    }
    else
    {
        uint64_t delta1 = pn64 - expected;
        uint64_t delta2 = not_mask_plus_one - delta1;

        if (delta2 <= delta1 && (pn64 & mask) > 0)
        {
            /* Out of sequence packet from previous roll */
            pn64 -= not_mask_plus_one;
        }
    }

    return pn64;
}

/*
 * Remove header protection
 */
int picoquic_remove_header_protection_inner(
    quic_packet_header* ph, void* pn_enc,
    unsigned int is_loss_bit_enabled_incoming,
    uint64_t sack_list_last)
{
    if (pn_enc == NULL)
    {
        /* The pn_enc algorithm was not initialized. Avoid crash! */
        ph->pn = 0xFFFFFFFF;
        ph->pnmask = 0xFFFFFFFF00000000ull;
        ph->pn64 = 0xFFFFFFFFFFFFFFFFull;

        DBG_PRINTF("PN dec not ready, type: %d, epoch: %d, pc: %d, pn: %d\n",
                   ph->ptype, ph->epoch, ph->pc, (int)ph->pn);

        return FNP_ERR_QUIC_AEAD_NOT_READY;
    }

    u8* bytes = ph->data;
    u8* decrypted_bytes = ph->packet->bytes;

    /* The header length is not yet known, will only be known after the sequence number is decrypted */
    int packet_len = ph->offset + ph->payload_length;
    size_t sample_offset = ph->offset + 4;
    size_t sample_size = picoquic_pn_iv_size(pn_enc);
    uint8_t mask_bytes[5] = {0, 0, 0, 0, 0};
    size_t mask_length = 5;
    if (sample_offset + sample_size > packet_len)
    {
        /* return an error */
        /* Invalid packet format. Avoid crash! */
        ph->pn = 0xFFFFFFFF;
        ph->pnmask = 0xFFFFFFFF00000000ull;

        DBG_PRINTF("Invalid packet length, type: %d, epoch: %d, pc: %d, pn-offset: %d, length: %d\n",
                   ph->ptype, ph->epoch, ph->pc, ph->offset, packet_len);
        return FNP_ERR_QUIC_DECRYPT_HEADER;
    }
    /* Decode */
    uint8_t first_byte = bytes[0];
    uint8_t first_mask = ((first_byte & 0x80) == 0x80)
                             ? 0x0F
                             : (is_loss_bit_enabled_incoming)
                             ? 0x07
                             : 0x1F;
    uint8_t pn_len;
    uint32_t pn_val = 0;

    // 此时offset指向pn的第一个字节
    rte_memcpy(decrypted_bytes, bytes, ph->offset);
    picoquic_pn_encrypt(pn_enc, bytes + sample_offset, mask_bytes, mask_bytes, mask_length);
    /* Decode the first byte */
    first_byte ^= (mask_bytes[0] & first_mask);
    pn_len = (first_byte & 3) + 1;
    ph->pnmask = (0xFFFFFFFFFFFFFFFFull);
    decrypted_bytes[0] = first_byte; // 将解密后的值写回解密数据包

    /* Packet encoding is 1 to 4 bytes */
    for (uint8_t i = 1; i <= pn_len; i++)
    {
        pn_val <<= 8;
        decrypted_bytes[ph->offset] = bytes[ph->offset] ^ mask_bytes[i];
        pn_val += decrypted_bytes[ph->offset++];
        ph->pnmask <<= 8;
    }

    /* Update the decrypt_mbuf  length */
    ph->pn = pn_val;
    ph->payload_length -= pn_len; // 去掉了pn的字节数
    /* Only set the key phase byte if short header */
    if (ph->ptype == picoquic_packet_1rtt_protected)
    {
        ph->key_phase = ((first_byte >> 2) & 1);
    }

    /* Build a packet number to 64 bits */
    ph->pn64 = picoquic_get_packet_number64(sack_list_last, ph->pnmask, ph->pn);

    /* 检查保留位 */
    if (!is_long_header_packet(first_byte))
    {
        ph->has_reserved_bit_set = !is_loss_bit_enabled_incoming && (first_byte & 0x18) != 0;
    }
    else
    {
        ph->has_reserved_bit_set = (first_byte & 0x0c) != 0;
    }

    return FNP_OK;
}

int picoquic_remove_header_protection(quic_cnx_t* cnx, quic_packet_header* ph)
{
    void* pn_enc = cnx->crypto_context[ph->epoch].pn_dec;
    picoquic_sack_list_t* sack_list = picoquic_sack_list_from_cnx_context(cnx, ph->pc, ph->lcid);
    return picoquic_remove_header_protection_inner(ph, pn_enc, cnx->is_loss_bit_enabled_incoming,
                                                   picoquic_sack_list_last(sack_list));
}

/*
 * Remove packet payload protection
 * 解密成功后，会修改ph->payload_length为解密后的payload长度
 */
int picoquic_remove_payload_protection(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int decoded;
    int ret = FNP_OK;
    u64 current_time = ph->current_time;
    u8* bytes = ph->data;
    u8* decoded_bytes = ph->packet->bytes;

    // 1-RTT包的解密
    if (ph->epoch == picoquic_epoch_1rtt)
    {
        int need_integrity_check = 1;
        picoquic_ack_context_t* ack_ctx = picoquic_ack_ctx_from_cnx_context(
            cnx, picoquic_packet_context_application, ph->lcid);

        /* Manage key rotation */
        if (ph->key_phase == cnx->key_phase_dec)
        {
            /* AEAD Decrypt */
            if (cnx->is_multipath_enabled && ph->ptype)
            {
                decoded = picoquic_aead_decrypt_mp(decoded_bytes + ph->offset,
                                                   bytes + ph->offset,
                                                   ph->payload_length,
                                                   ph->lcid->path_id, ph->pn64, decoded_bytes, ph->offset,
                                                   cnx->crypto_context[picoquic_epoch_1rtt].aead_decrypt);
            }
            else
            {
                decoded = picoquic_aead_decrypt_generic(decoded_bytes + ph->offset,
                                                        bytes + ph->offset, ph->payload_length, ph->pn64, decoded_bytes,
                                                        ph->offset,
                                                        cnx->crypto_context[picoquic_epoch_1rtt].aead_decrypt);
            }
            // 解密成功
            if (decoded <= ph->payload_length && ph->pn64 < ack_ctx->crypto_rotation_sequence)
            {
                ack_ctx->crypto_rotation_sequence = ph->pn64;
            }
        }
        else if ((ack_ctx->crypto_rotation_sequence == UINT64_MAX && current_time <= cnx->crypto_rotation_time_guard) ||
            ph->pn64 < ack_ctx->crypto_rotation_sequence)
        {
            /* This packet claims to be encoded with the old key */
            if (current_time > cnx->crypto_rotation_time_guard)
            {
                /* Too late. Ignore the packet. Could be some kind of attack. */
                return FNP_ERR_QUIC_PARSE_PACKET;
            }

            if (cnx->crypto_context_old.aead_decrypt == NULL)
            {
                /* old context is either not yet available, or already removed */
                decoded = ph->payload_length + 1;
                need_integrity_check = 0;
                return PICOQUIC_ERROR_AEAD_CHECK;
            }
            if (cnx->is_multipath_enabled)
            {
                decoded = picoquic_aead_decrypt_mp(decoded_bytes + ph->offset, bytes + ph->offset, ph->payload_length,
                                                   ph->lcid->path_id, ph->pn64, decoded_bytes, ph->offset,
                                                   cnx->crypto_context_old.aead_decrypt);
            }
            else
            {
                decoded = picoquic_aead_decrypt_generic(decoded_bytes + ph->offset, bytes + ph->offset,
                                                        ph->payload_length,
                                                        ph->pn64, decoded_bytes, ph->offset,
                                                        cnx->crypto_context_old.aead_decrypt);
            }
        }
        else
        {
            /* TODO: check that this is larger than last received with current key */
            /* These could only be a new key */
            if (cnx->crypto_context_new.aead_decrypt == NULL &&
                cnx->crypto_context_new.aead_encrypt == NULL)
            {
                /* If the new context was already computed, don't do it again */
                ret = picoquic_compute_new_rotated_keys(cnx);
            }
            /* if decoding succeeds, the rotation should be validated */
            if (ret == 0 && cnx->crypto_context_new.aead_decrypt != NULL)
            {
                if (cnx->is_multipath_enabled)
                {
                    decoded = picoquic_aead_decrypt_mp(decoded_bytes + ph->offset, bytes + ph->offset,
                                                       ph->payload_length,
                                                       ph->lcid->path_id, ph->pn64, decoded_bytes, ph->offset,
                                                       cnx->crypto_context_new.aead_decrypt);
                }
                else
                {
                    decoded = picoquic_aead_decrypt_generic(decoded_bytes + ph->offset,
                                                            bytes + ph->offset, ph->payload_length, ph->pn64,
                                                            decoded_bytes, ph->offset,
                                                            cnx->crypto_context_new.aead_decrypt);
                }
                if (decoded <= ph->payload_length)
                {
                    /* Rotation only if the packet was correctly decrypted with the new key */
                    cnx->crypto_rotation_time_guard = current_time + cnx->path[0]->retransmit_timer;
                    if (cnx->is_multipath_enabled)
                    {
                        for (int i = 0; i < cnx->nb_paths; i++)
                        {
                            cnx->path[i]->ack_ctx.crypto_rotation_sequence = UINT64_MAX;
                        }
                    }
                    ack_ctx->crypto_rotation_sequence = ph->pn64;
                    picoquic_apply_rotated_keys(cnx, 0);
                    cnx->nb_crypto_key_rotations++;

                    if (cnx->crypto_context_new.aead_encrypt != NULL)
                    {
                        /* If that move was not already validated, move to the new encryption keys */
                        picoquic_apply_rotated_keys(cnx, 1);
                    }
                }
            }
            else
            {
                /* new context could not be computed  */
                decoded = ph->payload_length + 1;
                need_integrity_check = 0;
            }
        }

        if (need_integrity_check && decoded > ph->payload_length)
        {
            cnx->crypto_failure_count++;
            if (cnx->crypto_failure_count > picoquic_aead_integrity_limit(
                cnx->crypto_context[picoquic_epoch_1rtt].aead_decrypt))
            {
                picoquic_log_app_message(cnx, "AEAD Integrity limit reached after 0x%" PRIx64 " failed decryptions.",
                                         cnx->crypto_failure_count);
                (void)picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_AEAD_LIMIT_REACHED, 0);
            }
        }
    }
    else
    {
        /* TODO: get rid of handshake some time after handshake complete */
        /* For all the other epochs, there is a single crypto context and no key rotation */
        if (cnx->crypto_context[ph->epoch].aead_decrypt != NULL)
        {
            decoded = picoquic_aead_decrypt_generic(decoded_bytes + ph->offset,
                                                    bytes + ph->offset, ph->payload_length, ph->pn64, decoded_bytes,
                                                    ph->offset, cnx->crypto_context[ph->epoch].aead_decrypt);
        }
        else
        {
            return PICOQUIC_ERROR_AEAD_NOT_READY;
        }
    }

    if (decoded > ph->payload_length)
        return PICOQUIC_ERROR_AEAD_CHECK;

    ph->payload_length = decoded;
    /* by conventions, values larger than input indicate error */
    return FNP_OK;
}

int quic_handle_stateless_reset_packet(quic_cnx_t* cnx, quic_packet_header* ph)
{
    // 判断是否是无状态重置数据包
    if (ph->ptype != picoquic_packet_1rtt_protected)
        return FNP_OK;

    int len = ph->offset + ph->payload_length;
    if (len < PICOQUIC_RESET_PACKET_MIN_SIZE)
        return FNP_OK;

    if (cnx == NULL)
    {
        // 不是无状态重置数据包，丢弃
        // cnx = picoquic_cnx_by_secret(quic, bytes + length - PICOQUIC_RESET_SECRET_SIZE, addr_from);
        // if (cnx != NULL)
        // {
        //     // ret = PICOQUIC_ERROR_STATELESS_RESET;
        //     picoquic_log_app_message(cnx, "Found connection from reset secret, ret = %d", ret);
        // }
        return FNP_OK;
    }

    u8* reset_scret = cnx->path[0]->first_tuple->p_remote_cnxid->reset_secret;
    if (memcmp(ph->data + len - PICOQUIC_RESET_SECRET_SIZE, reset_scret, PICOQUIC_RESET_SECRET_SIZE) == 0)
    {
        picoquic_log_app_message(cnx, "Decrypt error, matching reset secret");
        return PICOQUIC_ERROR_STATELESS_RESET;
    }

    return FNP_OK;
}

int quic_decrypt_packet(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = FNP_OK;
    quic_packet_t* packet = quic_create_packet(PICOQUIC_MAX_PACKET_SIZE);
    if (packet == NULL)
    {
        return FNP_ERR_MALLOC;
    }
    ph->packet = packet;

    int packet_len = ph->offset + ph->payload_length;

    if (ph->ptype == picoquic_packet_version_negotiation ||
        ph->ptype == picoquic_packet_retry)
    {
        fnp_memcpy(packet->bytes, ph->data, packet_len);
        return FNP_OK;
    }

    ret = picoquic_remove_header_protection(cnx, ph);
    CHECK_RET(ret);

    ret = picoquic_remove_payload_protection(cnx, ph);
    CHECK_RET(ret);

    // 判断有没有接收过该数据包
    if (picoquic_is_pn_already_received(cnx, ph->pc, ph->lcid, ph->pn64) != 0)
    {
        return PICOQUIC_ERROR_DUPLICATE;
    }

    // 从mbuf中移除该quic数据包
    rte_pktmbuf_adj(ph->mbuf, packet_len);
    packet->header_length = ph->offset;
    packet->length = ph->payload_length + ph->offset;

    return FNP_OK;
}

int quic_verify_packet(quic_cnx_t* cnx, quic_packet_header* ph)
{
    // check version index
    if (ph->version_index != cnx->version_index)
    {
        return FNP_ERR_QUIC_VERSION;
    }

    // 检查保留位
    if (ph->ptype != picoquic_packet_retry && ph->ptype != picoquic_packet_version_negotiation)
    {
        if (ph->has_reserved_bit_set)
        {
            return picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
        }
    }

    if (ph->ptype == picoquic_packet_initial)
    {
        if (ph->payload_length == 0)
        {
            /* empty payload! */
            return picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
        }

        // 检查initial packet的长度，应该丢弃
        if (ph->max_data_len < PICOQUIC_ENFORCED_INITIAL_MTU)
        {
            if (!cnx->did_receive_short_initial)
            {
                picoquic_log_app_message(cnx, "Received unpadded initial, length=%zu", ph->max_data_len);
            }
            cnx->did_receive_short_initial = 1;
            return PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        }

        // 对于服务端，第一次创建cnx时，lcid不存在，判断dcid是否等于icid
        if (!cnx->client_mode && picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->initial_cnxid) != 0)
        {
            return PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }

        // 不需要校验dcid与lcid是否相同了，肯定是相同的
        // 校验scid是否与本地保存的rcid相同
        // 对于客户端的conn，第一次收到initial packet时，rcid为空，
        if (picoquic_is_connection_id_null(&cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id))
        {
            // 第一次收到initial packet时，rcid为空，赋值。
            cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id = ph->srce_cnx_id;
        }
        else if (picoquic_compare_connection_id(&cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id,
                                                &ph->srce_cnx_id) != 0)
        {
            // 保存的rcid不为空，可能已经收到过initial
            printf("Error wrong srce cnxid (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                   cnx->client_mode, ph->ptype, ph->epoch, ph->pc, (int)ph->pn);
            return PICOQUIC_ERROR_CNXID_CHECK;
        }
    }
    else if (ph->ptype == picoquic_packet_1rtt_protected)
    {
        if (ph->payload_length == 0)
        {
            /* empty payload! */
            return picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
        }
    }

    return FNP_OK;
}

/*
 * Processing of a version renegotiation packet.
 *
 * From the specification: When the client receives a Version Negotiation packet
 * from the server, it should select an acceptable protocol version. If the server
 * lists an acceptable version, the client selects that version and reattempts to
 * create a connection using that version. Though the contents of a packet might
 * not change in response to version negotiation, a client MUST increase the packet
 * number it uses on every packet it sends. Packets MUST continue to use long headers
 * and MUST include the new negotiated protocol version.
 */
int picoquic_incoming_version_negotiation(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = 0;
    uint8_t* bytes = ph->packet->bytes;
    size_t length = ph->payload_length + ph->offset;

    /* Check the connection state */
    if (cnx->cnx_state != picoquic_state_client_init_sent)
    {
        /* This is an unexpected packet. Log and drop.*/
        DBG_PRINTF("Unexpected VN packet (%d), state %d, type: %d, epoch: %d, pc: %d, pn: %d\n",
                   cnx->client_mode, cnx->cnx_state, ph->ptype, ph->epoch, ph->pc, (int)ph->pn);
    }
    else if (picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[0]->first_tuple->p_local_cnxid->cnx_id) != 0 ||
        ph->vn != 0)
    {
        /* Packet destination ID does not match local CID, should be logged and ignored */
        DBG_PRINTF("VN packet (%d), does not pass echo test.\n", cnx->client_mode);
        ret = PICOQUIC_ERROR_DETECTED;
    }
    else if (picoquic_compare_connection_id(&ph->srce_cnx_id, &cnx->initial_cnxid) != 0 || ph->vn != 0)
    {
        /* Packet destination ID does not match initial DCID, should be logged and ignored */
        DBG_PRINTF("VN packet (%d), does not pass echo test.\n", cnx->client_mode);
        ret = PICOQUIC_ERROR_DETECTED;
    }
    else
    {
        /* Add DOS resilience */
        const uint8_t* v_bytes = bytes + ph->offset;
        const uint8_t* bytes_max = bytes + length;
        int nb_vn = 0;
        while (v_bytes < bytes_max)
        {
            uint32_t vn = 0;
            if ((v_bytes = picoquic_frames_uint32_decode(v_bytes, bytes_max, &vn)) == NULL)
            {
                DBG_PRINTF("VN packet (%d), length %zu, coding error after %d version numbers.\n",
                           cnx->client_mode, length, nb_vn);
                ret = PICOQUIC_ERROR_DETECTED;
                break;
            }
            else if (vn == cnx->proposed_version || vn == 0)
            {
                DBG_PRINTF("VN packet (%d), proposed_version[%d] = 0x%08x.\n", cnx->client_mode, nb_vn, vn);
                ret = PICOQUIC_ERROR_DETECTED;
                break;
            }
            else if (picoquic_get_version_index(vn) >= 0)
            {
                /* The VN packet proposes a valid version that is locally supported */
                nb_vn++;
            }
        }
        if (ret == 0)
        {
            if (nb_vn == 0)
            {
                DBG_PRINTF("VN packet (%d), does not propose any interesting version.\n", cnx->client_mode);
                ret = PICOQUIC_ERROR_DETECTED;
            }
            else
            {
                /* Signal VN to the application */
                // if (cnx->callback_fn && length > ph->offset)
                // {
                //     (void)(cnx->callback_fn)(cnx, 0, bytes + ph->offset, length - ph->offset,
                //                              picoquic_callback_version_negotiation, cnx->callback_ctx, NULL);
                // }
                /* TODO: consider rewriting the version negotiation code */
                DBG_PRINTF("%s", "Disconnect upon receiving version negotiation.\n");
                cnx->remote_error = PICOQUIC_ERROR_VERSION_NEGOTIATION;
                picoquic_connection_disconnect(cnx);
                ret = 0;
            }
        }
    }

    return ret;
}

/*
 * Send a version negotiation packet in response to an incoming packet
 * sporting the wrong version number. This assumes that the original packet
 * is at least 517 bytes long.
 */
void picoquic_prepare_version_negotiation(quic_context_t* quic, quic_packet_header* ph)
{
    u8* original_bytes = ph->data;

    quic_cnx_t* cnx = NULL;
    uint8_t dcid_length = original_bytes[5];
    uint8_t* dcid = original_bytes + 6;
    uint8_t scid_length = original_bytes[6 + dcid_length];
    uint8_t* scid = original_bytes + 6 + dcid_length + 1;


    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);
    // TODO: 检查cnx是否存在, 这里删除了检查逻辑，仅cnx不存在时进行版本协商
    if (sp != NULL)
    {
        u8* bytes = sp->bytes;
        size_t byte_index = 0;
        uint32_t rand_vn;

        /* Packet type set to random value for version negotiation */
        picoquic_public_random(bytes + byte_index, 1);
        bytes[byte_index++] |= 0x80;
        /* Set the version number to zero */
        picoformat_32(bytes + byte_index, 0);
        byte_index += 4;

        /* Copy the connection identifiers */
        bytes[byte_index++] = scid_length;
        memcpy(bytes + byte_index, scid, scid_length);
        byte_index += scid_length;
        bytes[byte_index++] = dcid_length;
        memcpy(bytes + byte_index, dcid, dcid_length);
        byte_index += dcid_length;

        /* Set the payload to the list of versions */
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
        {
            picoformat_32(bytes + byte_index, picoquic_supported_versions[i].version);
            byte_index += 4;
        }
        /* Add random reserved value as grease, but be careful to not match proposed version */
        do
        {
            rand_vn = (((uint32_t)picoquic_public_random_64()) & 0xF0F0F0F0) | 0x0A0A0A0A;
        }
        while (rand_vn == ph->vn);
        picoformat_32(bytes + byte_index, rand_vn);
        byte_index += 4;

        /* Set length and addresses, and queue. */
        rte_pktmbuf_append(sp->mbuf, byte_index);

        fsockaddr_copy(&sp->remote, &ph->remote);
        fsockaddr_copy(&sp->local, &ph->local);
        sp->initial_cid = ph->dest_cnx_id;
        sp->cnxid_log64 = picoquic_val64_connection_id(sp->initial_cid);
        sp->ptype = picoquic_packet_version_negotiation;

        // picoquic_log_quic_pdu(quic, 1, picoquic_get_quic_time(quic), 0, addr_to, addr_from, sp->length);

        picoquic_enqueue_stateless_packet(quic, sp);
    }
}

/*
 * Process an unexpected connection ID. This could be an old packet from a
 * previous connection. If the packet type correspond to an encrypted value,
 * the server can respond with a public reset.
 *
 * Per draft 14, the stateless reset starts with the packet code 0K110000.
 * The packet has after the first byte at least 23 random bytes, and then
 * the 16 bytes reset token.
 *
 * The "pad size" is computed so that the packet length is always at least
 * 1 byte shorter than the incoming packet. Since the minimum size of a
 * stateless reset is PICOQUIC_RESET_PACKET_MIN_SIZE, this code only
 * respond to packets that are strictly larger than the size.
 *
 *
 */
void picoquic_process_unexpected_cnxid(
    quic_context_t* quic,
    size_t length,
    quic_packet_header* ph,
    uint64_t current_time)
{
    if (length > PICOQUIC_RESET_PACKET_MIN_SIZE &&
        ph->ptype == picoquic_packet_1rtt_protected &&
        quic->stateless_reset_next_time <= current_time)
    {
        picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);
        if (sp != NULL)
        {
            size_t pad_size = length - PICOQUIC_RESET_SECRET_SIZE - 2;
            uint8_t* bytes = sp->bytes;
            size_t byte_index = 0;

            if (pad_size > PICOQUIC_RESET_PACKET_MIN_SIZE - PICOQUIC_RESET_SECRET_SIZE - 1)
            {
                pad_size -= (size_t)picoquic_public_uniform_random(
                    pad_size - (PICOQUIC_RESET_PACKET_MIN_SIZE - PICOQUIC_RESET_SECRET_SIZE - 1));
            }

            /* Packet type set to short header, randomize the 5 lower bits */
            bytes[byte_index++] = 0x40 | (uint8_t)(picoquic_public_random_64() & 0x3F);

            /* Add the random bytes */
            picoquic_public_random(bytes + byte_index, pad_size);
            byte_index += pad_size;
            /* Add the public reset secret */
            (void)picoquic_create_cnxid_reset_secret(quic, &ph->dest_cnx_id, bytes + byte_index);
            byte_index += PICOQUIC_RESET_SECRET_SIZE;

            rte_pktmbuf_append(sp->mbuf, byte_index);
            sp->ptype = picoquic_packet_1rtt_protected;
            fsockaddr_copy(&sp->remote, &ph->remote);
            fsockaddr_copy(&sp->local, &ph->local);
            sp->initial_cid = ph->dest_cnx_id;
            sp->cnxid_log64 = picoquic_val64_connection_id(sp->initial_cid);

            picoquic_log_context_free_app_message(quic, &sp->initial_cid,
                                                  "Unexpected connection ID, sending stateless reset.\n");

            picoquic_enqueue_stateless_packet(quic, sp);
            quic->stateless_reset_next_time = current_time + quic->stateless_reset_min_interval;
        }
    }
}

/*
 * Queue a stateless retry packet
 */

void picoquic_queue_stateless_retry(quic_context_t* quic,
                                    quic_packet_header* ph,
                                    quic_connection_id_t* s_cid,
                                    const struct sockaddr* addr_from,
                                    const struct sockaddr* addr_to,
                                    unsigned long if_index_to,
                                    uint8_t* retry_token,
                                    size_t retry_token_length)
{
    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);
    void* integrity_aead = picoquic_find_retry_protection_context(quic, ph->version_index, 1);
    size_t checksum_length = (integrity_aead == NULL) ? 0 : picoquic_aead_get_checksum_length(integrity_aead);

    if (sp != NULL)
    {
        uint8_t* bytes = sp->bytes;
        size_t byte_index = 0;
        size_t header_length = 0;
        size_t pn_offset;
        size_t pn_length;

        byte_index = header_length = picoquic_create_long_header(
            picoquic_packet_retry,
            &ph->srce_cnx_id,
            s_cid,
            0 /* No grease bit here */,
            ph->vn,
            ph->version_index,
            0, /* Sequence number is not used */
            retry_token_length,
            retry_token,
            bytes,
            &pn_offset,
            &pn_length);

        /* Add the token to the payload. */
        if (byte_index + retry_token_length < PICOQUIC_MAX_PACKET_SIZE)
        {
            memcpy(bytes + byte_index, retry_token, retry_token_length);
            byte_index += retry_token_length;
        }

        /* In the old drafts, there is no header protection and the sender copies the ODCID
         * in the packet. In the recent draft, the ODCID is not sent but
         * is verified as part of integrity checksum */
        if (integrity_aead == NULL)
        {
            bytes[byte_index++] = ph->dest_cnx_id.id_len;
            byte_index += picoquic_format_connection_id(bytes + byte_index,
                                                        PICOQUIC_MAX_PACKET_SIZE - byte_index - checksum_length,
                                                        ph->dest_cnx_id);
        }
        else
        {
            /* Encode the retry integrity protection if required. */
            byte_index = picoquic_encode_retry_protection(integrity_aead, bytes, PICOQUIC_MAX_PACKET_SIZE, byte_index,
                                                          &ph->dest_cnx_id);
        }


        rte_pktmbuf_append(sp->mbuf, byte_index);
        sp->ptype = picoquic_packet_retry;
        fsockaddr_copy(&sp->remote, &ph->remote);
        fsockaddr_copy(&sp->local, &ph->local);
        sp->cnxid_log64 = picoquic_val64_connection_id(ph->dest_cnx_id);

        picoquic_enqueue_stateless_packet(quic, sp);
    }
}

int picoquic_queue_retry_packet(quic_context_t* quic, quic_packet_header* ph)
{
    const sockaddr_t* addr_from = (sockaddr_t*)&ph->remote;
    const sockaddr_t* addr_to = (sockaddr_t*)&ph->local;
    int if_index_to = ph->iface_id;
    uint64_t current_time = ph->current_time;

    int ret = 0;
    uint8_t token_buffer[256];
    size_t token_size;
    quic_connection_id_t s_cid = {0};


    picoquic_create_local_cnx_id(quic, &s_cid, quic->local_cnxid_length, ph->dest_cnx_id);

    if (picoquic_prepare_retry_token(quic, addr_from,
                                     current_time + PICOQUIC_TOKEN_DELAY_SHORT, &ph->dest_cnx_id,
                                     &s_cid, ph->pn, token_buffer, sizeof(token_buffer), &token_size) != 0)
    {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else
    {
        picoquic_queue_stateless_retry(quic, ph, &s_cid, addr_from, addr_to, if_index_to,
                                       token_buffer, token_size);
        ret = PICOQUIC_ERROR_RETRY;
    }

    return ret;
}

int picoquic_queue_busy_packet(quic_context_t* quic, quic_packet_header* ph)
{
    const sockaddr_t* addr_from = (sockaddr_t*)&ph->remote;
    const sockaddr_t* addr_to = (sockaddr_t*)&ph->local;
    int if_index_to = ph->iface_id;
    uint64_t current_time = ph->current_time;

    int ret = 0;
    quic_connection_id_t s_cid = {0};
    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);
    void* aead_ctx = NULL;
    void* pn_enc_ctx = NULL;

    if (sp != NULL)
    {
        sp->mbuf = alloc_mbuf();
        if (sp->mbuf == NULL)
            return FNP_ERR_MBUF_ALLOC;
        uint8_t* bytes = rte_pktmbuf_mtod(sp->mbuf, uint8_t*);
        size_t byte_index = 0;
        size_t header_length = 0;
        size_t pn_offset;
        size_t pn_length;
        /* Payload is the encoding of the simples connection close frame */
        uint8_t payload[4] = {picoquic_frame_type_connection_close, PICOQUIC_TRANSPORT_SERVER_BUSY, 0, 0};
        size_t payload_length = 0;

        picoquic_create_local_cnx_id(quic, &s_cid, quic->local_cnxid_length, ph->dest_cnx_id);

        /* Prepare long header:  Initial */
        byte_index = header_length = picoquic_create_long_header(
            picoquic_packet_initial,
            &ph->srce_cnx_id,
            &s_cid,
            0 /* No grease bit here */,
            ph->vn,
            ph->version_index,
            0, /* Sequence number 0 by default. */
            0,
            NULL,
            bytes,
            &pn_offset,
            &pn_length);

        /* Apply AEAD */
        if (picoquic_get_initial_aead_context(quic, ph, 0 /* is_client=0 */, 1 /* is_enc = 1 */, &aead_ctx, &pn_enc_ctx)
            == 0)
        {
            /* Make sure that the payload length is encoded in the header */
            /* Using encryption, the "payload" length also includes the encrypted packet length */
            picoquic_update_payload_length(bytes, pn_offset, header_length - pn_length,
                                           header_length + sizeof(payload) +
                                           picoquic_aead_get_checksum_length(aead_ctx));
            /* Encrypt packet payload */
            payload_length = picoquic_aead_encrypt_generic(bytes + header_length,
                                                           payload, sizeof(payload), 0, bytes, header_length, aead_ctx);
            /* protect the PN */
            picoquic_protect_packet_header(bytes, pn_offset, 0x0F, pn_enc_ctx);
            /* Fill up control fields */
            rte_pktmbuf_append(sp->mbuf, byte_index + payload_length);
            sp->ptype = picoquic_packet_initial;
            fsockaddr_copy(&sp->remote, &ph->remote);
            fsockaddr_copy(&sp->local, &ph->local);
            sp->cnxid_log64 = picoquic_val64_connection_id(ph->dest_cnx_id);
            /* Queue packet */
            picoquic_enqueue_stateless_packet(quic, sp);
        }

        if (aead_ctx != NULL)
        {
            /* Free the AEAD CTX */
            picoquic_aead_free(aead_ctx);
        }

        if (pn_enc_ctx != NULL)
        {
            /* Free the PN encryption context */
            picoquic_cipher_free(pn_enc_ctx);
        }
    }
    return ret;
}

/* Queue a close message for an incoming connection attempt that was rejected.
 * The connection context can then be immediately frees.
 */
void picoquic_enqueue_immediate_close(quic_cnx_t* cnx, uint64_t current_time)
{
    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(cnx->quic);
    if (sp == NULL)
    {
        return;
    }

    int len;
    int ret = picoquic_prepare_packet(cnx, current_time, &sp->local, &sp->remote, sp->bytes, &len);
    if (ret == 0 && len > 0)
    {
        rte_pktmbuf_append(sp->mbuf, len);
        picoquic_enqueue_stateless_packet(cnx->quic, sp);
    }
    else
    {
        picoquic_free_stateless_packet(sp);
    }
}

/*
 * Processing of initial or handshake messages when they are not expected
 * any more. These messages could be used in a DOS attack against the
 * connection, but they could also be legit messages sent by a peer
 * that does not implement implicit ACK. They are processed to not
 * cause any side effect, but to still generate ACK if the client
 * needs them.
 */

void picoquic_ignore_incoming_handshake(
    quic_cnx_t* cnx,
    uint8_t* bytes,
    quic_packet_header* ph,
    uint64_t current_time)
{
    /* The data starts at ph->index, and its length
     * is ph->payload_length. */
    int ret = 0;
    size_t byte_index = 0;
    int ack_needed = 0;
    picoquic_packet_context_enum pc;

    if (ph->ptype == picoquic_packet_initial)
    {
        pc = picoquic_packet_context_initial;
    }
    else if (ph->ptype == picoquic_packet_handshake)
    {
        pc = picoquic_packet_context_handshake;
    }
    else
    {
        /* Not expected! */
        return;
    }

    bytes += ph->offset;

    while (ret == 0 && byte_index < ph->payload_length)
    {
        size_t frame_length = 0;
        int frame_is_pure_ack = 0;
        ret = picoquic_skip_frame(&bytes[byte_index],
                                  ph->payload_length - byte_index, &frame_length, &frame_is_pure_ack);
        byte_index += frame_length;
        if (frame_is_pure_ack == 0)
        {
            ack_needed = 1;
        }
    }

    /* If the packet contains ackable data, mark ack needed
     * in the relevant packet context */
    if (ret == 0 && ack_needed)
    {
        picoquic_set_ack_needed(cnx, current_time, pc, cnx->path[0], 0);
    }
}

/*
 * 处理来自客户端的initial packet,
 * on an unknown connection context.
 */

int picoquic_incoming_client_initial(
    quic_cnx_t** pcnx,
    quic_packet_header* ph,
    int new_context_created)
{
    int ret = 0;
    uint8_t* bytes = ph->packet->bytes;
    int packet_length = ph->max_data_len;
    quic_packet_t* packet = ph->packet;
    fsockaddr_t* addr_from = &ph->remote;
    fsockaddr_t* addr_to = &ph->local;
    unsigned long if_index_to = ph->iface_id;
    uint64_t current_time = ph->current_time;

    if ((*pcnx)->path[0]->first_tuple->p_local_cnxid->cnx_id.id_len > 0 &&
        picoquic_compare_connection_id(&ph->dest_cnx_id, &(*pcnx)->path[0]->first_tuple->p_local_cnxid->cnx_id) == 0)
    {
        (*pcnx)->initial_validated = 1;
    }

    if (!(*pcnx)->initial_validated &&
        (*pcnx)->pkt_ctx[picoquic_packet_context_initial].pending_first != NULL &&
        packet_length >= PICOQUIC_ENFORCED_INITIAL_MTU)
    {
        /* In most cases, receiving more than 1 initial packets before validation indicates that the
         * client is repeating data that it believes is lost. We set the initial_repeat_needed flag
         * to trigger such repetitions. There are exceptions, e.g., clients sending large client hellos
         * that require multiple packets. These exceptions are detected and handled during packet
         * processing. */
        (*pcnx)->initial_repeat_needed = 1;
    }

    if ((*pcnx)->cnx_state == picoquic_state_server_init &&
        ((*pcnx)->quic->server_busy ||
            (*pcnx)->quic->current_number_connections > (*pcnx)->quic->tentative_max_number_connections))
    {
        (*pcnx)->local_error = PICOQUIC_TRANSPORT_SERVER_BUSY;
        (*pcnx)->cnx_state = picoquic_state_handshake_failure;
    }
    else if ((*pcnx)->cnx_state == picoquic_state_server_init &&
        (*pcnx)->initial_cnxid.id_len < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH)
    {
        (*pcnx)->local_error = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        (*pcnx)->cnx_state = picoquic_state_handshake_failure;
    }
    else if ((*pcnx)->cnx_state < picoquic_state_server_almost_ready)
    {
        /* Document the incoming addresses */
        fsockaddr_copy(&(*pcnx)->path[0]->first_tuple->local_addr, addr_to);
        fsockaddr_copy(&(*pcnx)->path[0]->first_tuple->peer_addr, addr_from);
        (*pcnx)->path[0]->first_tuple->if_index = if_index_to;

        /* decode the incoming frames */
        uint64_t highest_ack_before = (*pcnx)->pkt_ctx[picoquic_packet_context_initial].highest_acknowledged;
        ret = picoquic_decode_frames(*pcnx, (*pcnx)->path[0], packet, ph->epoch, addr_from, addr_to,
                                     ph->pn64, 0, current_time);
        if ((*pcnx)->pkt_ctx[picoquic_packet_context_initial].highest_acknowledged > highest_ack_before &&
            (*pcnx)->quic->random_initial > 1)
        {
            /* Randomized sequence number was acknowledged. Consider the
             * connection validated */
            (*pcnx)->initial_validated = 1;
        }

        /* processing of client initial packet */
        if (ret == 0)
        {
            int data_consumed = 0;
            /* initialization of context & creation of data */
            ret = picoquic_tls_stream_process(*pcnx, &data_consumed, current_time);
            /* The "initial_repeat_needed" flag is set if multiple initial packets are
             * received while the connection is not yet validated. In most cases, this indicates
             * that the client repeated some initial packets, or sent some gratuitous initial
             * packets, because it believes its own initial packet was lost. The flag forces
             * immediate retransmission of initial packets. However, there are cases when the
             * client sent large client hello messages that do not fit on a single packets. In
             * those cases, the flag should not be set. We detect that by testing whether new
             * TLS data was received in the packet. */
            if (data_consumed)
            {
                (*pcnx)->initial_repeat_needed = 0;
            }
        }
    }
    else if ((*pcnx)->cnx_state < picoquic_state_ready)
    {
        /* Require an acknowledgement if the packet contains ackable frames */
        picoquic_ignore_incoming_handshake(*pcnx, bytes, ph, current_time);
    }
    else
    {
        /* Initial keys should have been discarded, treat packet as unexpected */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    if (ret == PICOQUIC_ERROR_INVALID_TOKEN && (*pcnx)->cnx_state == picoquic_state_handshake_failure)
    {
        ret = 0;
    }

    if (ret == 0 && (*pcnx)->cnx_state == picoquic_state_handshake_failure && new_context_created)
    {
        picoquic_enqueue_immediate_close(*pcnx, current_time);
    }

    if (ret != 0 || (*pcnx)->cnx_state == picoquic_state_disconnected)
    {
        /* This is bad. If this is an initial attempt, delete the connection */
        if (new_context_created)
        {
            picoquic_delete_cnx(*pcnx);
            *pcnx = NULL;
            ret = PICOQUIC_ERROR_CONNECTION_DELETED;
        }
    }

    return ret;
}

/*
 * Processing of a server retry
 *
 * The packet number and connection ID fields echo the corresponding fields from the
 * triggering client packet. This allows a client to verify that the server received its packet.
 *
 * A Server Stateless Retry packet is never explicitly acknowledged in an ACK frame by a client.
 * Receiving another Client Initial packet implicitly acknowledges a Server Stateless Retry packet.
 *
 * After receiving a Server Stateless Retry packet, the client uses a new Client Initial packet
 * containing the next token. In effect, the next cryptographic
 * handshake message is sent on a new connection.
 */

int picoquic_incoming_retry(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = 0;

    uint8_t* bytes = ph->packet->bytes;
    uint64_t current_time = ph->current_time;

    size_t token_length = 0;
    uint8_t* token = NULL;

    if ((cnx->cnx_state != picoquic_state_client_init_sent && cnx->cnx_state != picoquic_state_client_init_resent) ||
        cnx->original_cnxid.id_len != 0)
    {
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }
    else
    {
        /* Verify that the header is a proper echo of what was sent */
        if (ph->vn != picoquic_supported_versions[cnx->version_index].version)
        {
            /* Packet that do not match the "echo" checks should be logged and ignored */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }
        else if (ph->pn64 != 0)
        {
            /* after draft-12, PN is required to be 0 */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }
    }

    if (ret == 0)
    {
        /* Parse the retry frame */
        void* integrity_aead = picoquic_find_retry_protection_context(cnx->quic, cnx->version_index, 0);
        size_t byte_index = ph->offset;
        size_t data_length = ph->offset + ph->payload_length;

        /* Assume that is aead context is null, this is the old format and the
         * integrity shall be verifed by checking the ODCID */
        if (integrity_aead == NULL)
        {
            uint8_t odcil = bytes[byte_index++];

            if (odcil != cnx->initial_cnxid.id_len || (size_t)odcil + 1u > ph->payload_length ||
                memcmp(cnx->initial_cnxid.id, &bytes[byte_index], odcil) != 0)
            {
                /* malformed ODCIL, or does not match initial cid; ignore */
                ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
                picoquic_log_app_message(cnx, "Retry packet rejected: odcid check failed");
            }
            else
            {
                byte_index += odcil;
            }
        }
        else
        {
            ret = picoquic_verify_retry_protection(integrity_aead, bytes, &data_length, byte_index,
                                                   &cnx->initial_cnxid);

            if (ret != 0)
            {
                picoquic_log_app_message(cnx, "Retry packet rejected: integrity check failed, ret=0x%x", ret);
            }
        }

        if (ret == 0)
        {
            token_length = data_length - byte_index;

            if (token_length > 0)
            {
                token = malloc(token_length);
                if (token == NULL)
                {
                    ret = PICOQUIC_ERROR_MEMORY;
                }
                else
                {
                    memcpy(token, &bytes[byte_index], token_length);
                }
            }
        }
    }

    if (ret == 0)
    {
        /* Close the log, because it is keyed by initial_cnxid */
        picoquic_log_close_connection(cnx);
        /* if this is the first reset, reset the original cid */
        if (cnx->original_cnxid.id_len == 0)
        {
            cnx->original_cnxid = cnx->initial_cnxid;
        }
        /* reset the initial CNX_ID to the version sent by the server */
        cnx->initial_cnxid = ph->srce_cnx_id;

        /* keep a copy of the retry token */
        if (cnx->retry_token != NULL)
        {
            free(cnx->retry_token);
        }
        cnx->retry_token = token;
        cnx->retry_token_length = (uint16_t)token_length;

        picoquic_reset_cnx(cnx, current_time);

        /* Mark the packet as not required for ack */
        ret = PICOQUIC_ERROR_RETRY;
    }

    return ret;
}

/*
 * 客户端处理来自服务端的initial packet
 */
int picoquic_incoming_server_initial(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = 0;
    uint8_t* bytes = ph->packet->bytes;
    int packet_length = ph->offset + ph->payload_length;
    quic_packet_t* packet = ph->packet;
    fsockaddr_t* addr_to = &ph->local;
    unsigned long if_index_to = ph->iface_id;
    uint64_t current_time = ph->current_time;

    if (cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent)
    {
        cnx->cnx_state = picoquic_state_client_handshake_start;
    }

    if (cnx->cnx_state <= picoquic_state_client_handshake_start)
    {
        /* 如果local addr不存在，则记录下来  */
        if (cnx->path[0]->first_tuple->local_addr.family == FSOCKADDR_NONE && addr_to != NULL)
        {
            fsockaddr_copy(&cnx->path[0]->first_tuple->local_addr, addr_to);
        }
        cnx->path[0]->first_tuple->if_index = if_index_to;
        /* Accept the incoming frames */
        /* Verify that the packet is long enough */
        // 为什么有这个处理？
        if (ph->max_data_len < PICOQUIC_ENFORCED_INITIAL_MTU)
        {
            size_t byte_index = ph->offset;
            int ack_needed = 0;
            int skip_ret = 0;

            while (skip_ret == 0 && byte_index < ph->payload_length)
            {
                size_t frame_length = 0;
                int frame_is_pure_ack = 0;
                skip_ret = picoquic_skip_frame(&bytes[byte_index], ph->payload_length - byte_index, &frame_length,
                                               &frame_is_pure_ack);
                byte_index += frame_length;
                if (frame_is_pure_ack == 0)
                {
                    ack_needed = 1;
                    break;
                }
            }
            if (ack_needed && cnx->retry_token_length == 0 && cnx->crypto_context[1].aead_encrypt == NULL)
            {
                /* perform the test on new paths, but not if resuming an existing path or session */
                picoquic_log_app_message(cnx, "Server initial too short (%zu bytes)", packet_length);
                return PICOQUIC_ERROR_INITIAL_TOO_SHORT;
            }
        }

        ret = picoquic_decode_frames(cnx, cnx->path[0], packet, ph->epoch, NULL, addr_to, ph->pn64, 0, current_time);
        CHECK_RET(ret);

        /* processing of initial packet */
        ret = picoquic_tls_stream_process(cnx, NULL, current_time);
        CHECK_RET(ret);
    }
    else if (cnx->cnx_state < picoquic_state_ready)
    {
        /* Require an acknowledgement if the packet contains ackable frames */
        picoquic_ignore_incoming_handshake(cnx, bytes, ph, current_time);
    }
    else
    {
        /* Initial keys should have been discarded, treat packet as unexpected */
        return PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return FNP_OK;
}

int picoquic_incoming_server_handshake(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = 0;
    uint8_t* bytes = ph->packet->bytes;
    quic_packet_t* packet = ph->packet;
    fsockaddr_t* addr_to = &ph->local;
    unsigned long if_index_to = ph->iface_id;
    uint64_t current_time = ph->current_time;

    int restricted = cnx->cnx_state != picoquic_state_client_handshake_start;

    if (picoquic_compare_connection_id(&cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id, &ph->srce_cnx_id) != 0)
    {
        return PICOQUIC_ERROR_CNXID_CHECK; /* protocol error */
    }

    if (cnx->cnx_state < picoquic_state_ready)
    {
        /* Accept the incoming frames */

        if (ph->payload_length == 0)
        {
            /* empty payload! */
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
        }
        else
        {
            ret = picoquic_decode_frames(cnx, cnx->path[0], packet,
                                         ph->epoch, NULL, addr_to, ph->pn64, 0, current_time);
        }

        /* processing of initial packet */
        if (ret == 0 && restricted == 0)
        {
            ret = picoquic_tls_stream_process(cnx, NULL, current_time);
        }
    }
    else
    {
        /* Initial keys should have been discarded, treat packet as unexpected */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
 * Processing of client handshake packet.
 */
int picoquic_incoming_client_handshake(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = 0;
    uint8_t* bytes = ph->packet->bytes;
    quic_packet_t* packet = ph->packet;
    uint64_t current_time = ph->current_time;

    cnx->initial_validated = 1;
    cnx->initial_repeat_needed = 0;

    if (cnx->cnx_state < picoquic_state_server_almost_ready)
    {
        if (picoquic_compare_connection_id(&ph->srce_cnx_id, &cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id) != 0)
        {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        }
        else
        {
            /* Accept the incoming frames */
            if (ph->payload_length == 0)
            {
                /* empty payload! */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else
            {
                ret = picoquic_decode_frames(cnx, cnx->path[0], packet,
                                             ph->epoch, NULL, NULL, ph->pn64, 0, current_time);
            }
            /* processing of client clear text packet */
            if (ret == 0)
            {
                /* Any successful handshake packet is an explicit ack of initial packets */
                picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
                picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);

                /* If TLS data present, progress the TLS state */
                ret = picoquic_tls_stream_process(cnx, NULL, current_time);

                /* If TLS FIN has been received, the server side handshake is ready */
                if (!cnx->client_mode && cnx->cnx_state < picoquic_state_ready && picoquic_is_tls_complete(cnx))
                {
                    picoquic_ready_state_transition(cnx, current_time);
                }
            }
        }
    }
    else if (cnx->cnx_state <= picoquic_state_ready)
    {
        /* Because the client is never guaranteed to discard handshake keys,
         * we need to keep it for the duration of the connection.
         * Process the incoming frames, ignore them, but
         * require an acknowledgement if the packet contains ackable frames */
        picoquic_ignore_incoming_handshake(cnx, bytes, ph, current_time);
    }
    else
    {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
 * 处理收到的无状态重置包.
 */
int picoquic_incoming_stateless_reset(quic_cnx_t* cnx)
{
    /* Stateless reset. The connection should be abandonned */
    if (cnx->cnx_state <= picoquic_state_ready)
    {
        cnx->remote_error = PICOQUIC_ERROR_STATELESS_RESET;
    }
    // if (cnx->callback_fn)
    // {
    //     (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_stateless_reset, cnx->callback_ctx, NULL);
    // }
    picoquic_connection_disconnect(cnx);

    return PICOQUIC_ERROR_AEAD_CHECK;
}

/*
 * Processing of 0-RTT packet
 */

int picoquic_incoming_0rtt(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int ret = 0;
    uint8_t* bytes = ph->packet->bytes;
    quic_packet_t* packet = ph->packet;
    uint64_t current_time = ph->current_time;

    if (!(picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->initial_cnxid) == 0 ||
            picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[0]->first_tuple->p_local_cnxid->cnx_id) == 0) ||
        picoquic_compare_connection_id(&ph->srce_cnx_id, &cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id) != 0)
    {
        ret = PICOQUIC_ERROR_CNXID_CHECK;
    }
    else if (cnx->cnx_state == picoquic_state_server_almost_ready ||
        cnx->cnx_state == picoquic_state_server_false_start ||
        (cnx->cnx_state == picoquic_state_ready && !cnx->is_1rtt_received))
    {
        if (ph->vn != picoquic_supported_versions[cnx->version_index].version)
        {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
        }
        else
        {
            /* Accept the incoming frames */
            if (ph->payload_length == 0)
            {
                /* empty payload! */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else
            {
                cnx->nb_zero_rtt_received++;
                ret = picoquic_decode_frames(cnx, cnx->path[0], packet,
                                             ph->epoch, NULL, NULL, ph->pn64, 0, current_time);
            }

            if (ret == 0)
            {
                /* Processing of TLS messages -- EOED */
                ret = picoquic_tls_stream_process(cnx, NULL, current_time);
            }
        }
    }
    else
    {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
 * ECN Accounting. This is only called if the packet was processed successfully.
 */
void picoquic_ecn_accounting(quic_cnx_t* cnx,
                             unsigned char received_ecn, picoquic_packet_context_enum pc, picoquic_local_cnxid_t* l_cid)
{
    picoquic_ack_context_t* ack_ctx = &cnx->ack_ctx[pc];

    if (pc == picoquic_packet_context_application && cnx->is_multipath_enabled)
    {
        ack_ctx = picoquic_ack_ctx_from_cnx_context(cnx, pc, l_cid);
    }

    switch (received_ecn & 0x03)
    {
    case 0x00:
        break;
    case 0x01: /* ECN_ECT_1 */
        ack_ctx->ecn_ect1_total_local++;
        ack_ctx->sending_ecn_ack |= 1;
        break;
    case 0x02: /* ECN_ECT_0 */
        ack_ctx->ecn_ect0_total_local++;
        ack_ctx->sending_ecn_ack |= 1;
        break;
    case 0x03: /* ECN_CE */
        ack_ctx->ecn_ce_total_local++;
        ack_ctx->sending_ecn_ack |= 1;
        break;
    }
}

/*
 * Processing of client encrypted packet.
 */
int picoquic_incoming_1rtt(quic_cnx_t* cnx, int path_id, quic_packet_header* ph)
{
    int ret = 0;
    u8* bytes = ph->packet->bytes;
    quic_packet_t* packet = ph->packet; // decrypted_data
    fsockaddr_t* addr_from = &ph->remote;
    fsockaddr_t* addr_to = &ph->local;
    int if_index_to = 0;
    unsigned char received_ecn = ph->ecn;
    int path_is_not_allocated = 0;
    uint64_t current_time = ph->current_time;

    /* Check the packet */
    if (cnx->cnx_state < picoquic_state_client_almost_ready)
    {
        /* handshake is not complete. Just ignore the packet */
        return PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    if (cnx->cnx_state == picoquic_state_disconnected)
    {
        /* Connection is disconnected. Just ignore the packet */
        return PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }
    /* Packet is correct */
    /* TODO: consider treatment of migration during closing mode */

    /* Do not process data in closing or draining modes */
    if (cnx->cnx_state >= picoquic_state_disconnecting)
    {
        /* only look for closing frames in closing modes */
        if (cnx->cnx_state == picoquic_state_closing || cnx->cnx_state == picoquic_state_disconnecting)
        {
            int closing_received = 0;

            ret = picoquic_decode_closing_frames(
                cnx, bytes + ph->offset, ph->payload_length, &closing_received);

            if (ret == 0)
            {
                if (closing_received)
                {
                    if (cnx->client_mode)
                    {
                        picoquic_connection_disconnect(cnx);
                    }
                    else
                    {
                        cnx->cnx_state = picoquic_state_draining;
                    }
                }
                else
                {
                    picoquic_set_ack_needed(cnx, current_time, ph->pc, cnx->path[path_id], 0);
                }
            }
        }
        else
        {
            /* Just ignore the packets in closing received or draining mode */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }
    }
    else if (ret == 0)
    {
        picoquic_path_t* path_x = cnx->path[path_id];

        path_x->first_tuple->if_index = if_index_to;
        cnx->is_1rtt_received = 1;
        picoquic_spin_function_table[cnx->spin_policy].spinbit_incoming(cnx, path_x, ph);
        /* Accept the incoming frames */
        ret = picoquic_decode_frames(cnx, cnx->path[path_id], packet,
                                     ph->epoch, addr_from, addr_to, ph->pn64,
                                     path_is_not_allocated, current_time);

        if (ret == 0)
        {
            /* Compute receive bandwidth */
            path_x->received += (uint64_t)ph->offset + ph->payload_length +
                picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
            if (path_x->receive_rate_epoch == 0)
            {
                path_x->received_prior = cnx->path[path_id]->received;
                path_x->receive_rate_epoch = current_time;
            }
            else
            {
                uint64_t delta = current_time - cnx->path[path_id]->receive_rate_epoch;
                if (delta > path_x->smoothed_rtt && delta > PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN)
                {
                    path_x->receive_rate_estimate = ((cnx->path[path_id]->received - cnx->path[path_id]->received_prior)
                        * 1000000) / delta;
                    path_x->received_prior = cnx->path[path_id]->received;
                    path_x->receive_rate_epoch = current_time;
                    if (path_x->receive_rate_estimate > cnx->path[path_id]->receive_rate_max)
                    {
                        path_x->receive_rate_max = cnx->path[path_id]->receive_rate_estimate;
                        if (path_id == 0)
                        {
                            picoquic_compute_ack_gap_and_delay(cnx, cnx->path[0]->rtt_min, PICOQUIC_ACK_DELAY_MIN,
                                                               cnx->path[0]->receive_rate_max, &cnx->ack_gap_remote,
                                                               &cnx->ack_delay_remote);
                        }
                    }
                }
            }

            /* Processing of TLS messages  */
            ret = picoquic_tls_stream_process(cnx, NULL, current_time);
        }

        if (ret == 0 && picoquic_cnx_is_still_logging(cnx))
        {
            picoquic_log_cc_dump(cnx, current_time);
        }
    }

    return ret;
}

/* Processing of packets received before they could be fully decrypted
 */
int picoquic_incoming_not_decrypted(quic_cnx_t* cnx, quic_packet_header* ph)
{
    int buffered = 0;
    uint64_t current_time = ph->current_time;
    fsockaddr_t* addr_from = &ph->remote;
    fsockaddr_t* addr_to = &ph->local;
    unsigned char received_ecn = ph->ecn;

    if (cnx->cnx_state < picoquic_state_ready)
    {
        if (cnx->path[0]->first_tuple->p_local_cnxid->cnx_id.id_len > 0 &&
            picoquic_compare_connection_id(&cnx->path[0]->first_tuple->p_local_cnxid->cnx_id, &ph->dest_cnx_id) == 0)
        {
            /* verifying the destination cnx id is a strong hint that the peer is responding.
             * Setting epoch parameter = -1 guarantees the hint is only used if the RTT is not
             * yet known.
             */
            picoquic_update_path_rtt(cnx, cnx->path[0], cnx->path[0], -1, cnx->start_time, current_time, 0, 0);

            if (ph->max_data_len <= PICOQUIC_MAX_PACKET_SIZE &&
                ((ph->ptype == picoquic_packet_handshake && cnx->client_mode) || ph->ptype ==
                    picoquic_packet_1rtt_protected))
            {
                /* stash a copy of the incoming message for processing once the keys are available */
                picoquic_stateless_packet_t* packet = picoquic_create_stateless_packet(cnx->quic);
                if (packet != NULL)
                {
                    packet->ptype = ph->ptype;
                    packet->mbuf = clone_mbuf(ph->mbuf);
                    packet->next_packet = cnx->first_sooner;
                    cnx->first_sooner = packet;
                    fsockaddr_copy(&packet->local, addr_to);
                    fsockaddr_copy(&packet->remote, addr_from);
                    packet->received_ecn = received_ecn;
                    packet->receive_time = current_time;
                    buffered = 1;
                }
            }
        }
    }

    return buffered;
}

/* 处理收到的暂存的数据包，由于加密上下文还未协商完成时 */
void picoquic_process_sooner_packets(quic_cnx_t* cnx, uint64_t current_time)
{
    picoquic_stateless_packet_t* packet = cnx->first_sooner;
    picoquic_stateless_packet_t* previous = NULL;

    cnx->recycle_sooner_needed = 0;

    while (packet != NULL)
    {
        picoquic_stateless_packet_t* next_packet = packet->next_packet;
        int could_try_now = 1;
        picoquic_epoch_enum epoch = 0;
        switch (packet->ptype)
        {
        case picoquic_packet_handshake:
            epoch = picoquic_epoch_handshake;
            break;
        case picoquic_packet_1rtt_protected:
            epoch = picoquic_epoch_1rtt;
            break;
        default:
            could_try_now = 0;
            break;
        }

        if (could_try_now &&
            (cnx->crypto_context[epoch].aead_decrypt != NULL || cnx->crypto_context[epoch].pn_dec != NULL))
        {
            quic_handle_incoming_udp_mbuf(cnx->quic, packet->mbuf, packet->receive_time, current_time);

            if (previous == NULL)
            {
                cnx->first_sooner = packet->next_packet;
            }
            else
            {
                previous->next_packet = packet->next_packet;
            }
            picoquic_free_stateless_packet(packet);
        }
        else
        {
            previous = packet;
        }

        packet = next_packet;
    }
}



