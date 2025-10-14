#ifndef FNP_TCP_OUT_H
#define FNP_TCP_OUT_H

#include "tcp_sock.h"


void tcp_send_init();

// 准备进行重传, 可能是定时器超时，
void tcp_start_retransmit(tcp_sock_t* sock);

void tcp_ack_pending_list(tcp_sock_t* sock, u32 ack);

void tcp_send_syn(tcp_sock_t* sock);

void tcp_send_fin(tcp_sock_t* sock);

void tcp_send_ack(tcp_sock_t* sock, bool delay);

void tcp_send_rst(tcp_segment* seg);

void tcp_send(tcp_sock_t* sock);

#endif // FNP_TCP_OUT_H
