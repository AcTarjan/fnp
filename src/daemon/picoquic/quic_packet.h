#ifndef QUIC_PACKET_H
#define QUIC_PACKET_H

#include "fnp_common.h"
#include "picoquic_internal.h"

#define is_potential_quic_packet(firstByte) ((firstByte) & 0x40) > 0
#define is_long_header_packet(firstByte) ((firstByte) & 0x80) > 0

int quic_parse_packet_header(
    quic_context_t* quic, quic_packet_header* ph, struct rte_mbuf* m, u64 current_time);

int quic_handle_statless_reset_packet(quic_cnx_t* cnx, quic_packet_header* ph);

int quic_decrypt_packet(quic_cnx_t* cnx, quic_packet_header* ph);

int quic_verify_packet(quic_cnx_t* cnx, quic_packet_header* ph);

int picoquic_incoming_stateless_reset(quic_cnx_t* cnx);

// 服务端接收一个新的连接
int quic_server_handle_initial_packet(quic_context_t* quic, quic_cnx_t** pcnx, quic_packet_header* ph);

// 进行版本协商
void picoquic_prepare_version_negotiation(quic_context_t* quic, quic_packet_header* ph);

// 处理来自服务端的初始包
int picoquic_incoming_server_initial(quic_cnx_t* cnx, quic_packet_header* ph);

// 处理来自服务端的重试包
int picoquic_incoming_retry(quic_cnx_t* cnx, quic_packet_header* ph);

// 处理来自服务端的版本协商包
int picoquic_incoming_version_negotiation(quic_cnx_t* cnx, quic_packet_header* ph);

// 处理来自服务端的握手包
int picoquic_incoming_server_handshake(quic_cnx_t* cnx, quic_packet_header* ph);

/*****     服务端处理         ****/

// 处理来自客户端的初始包
int picoquic_incoming_client_initial(
    quic_cnx_t** pcnx, quic_packet_header* ph, int new_context_created);

// 处理来自客户端的握手包
int picoquic_incoming_client_handshake(quic_cnx_t* cnx, quic_packet_header* ph);

int picoquic_incoming_0rtt(quic_cnx_t* cnx, quic_packet_header* ph);

int picoquic_incoming_1rtt(quic_cnx_t* cnx, int path_id, quic_packet_header* ph);

void picoquic_ecn_accounting(quic_cnx_t* cnx,
                             unsigned char received_ecn, picoquic_packet_context_enum pc,
                             picoquic_local_cnxid_t* l_cid);
#endif
