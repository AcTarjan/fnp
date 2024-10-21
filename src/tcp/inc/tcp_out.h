#ifndef FNP_TCP_OUT_H
#define FNP_TCP_OUT_H

#include "tcp_sock.h"
#include "tcp_in.h"

void tcp_send_ack(tcp_sock_t* sk, bool delay);

void tcp_send_rst(tcp_seg_t* seg);

void tcp_data_send(tcp_sock_t* sk);

void tcp_syn_send(tcp_sock_t* sk);

#endif //FNP_TCP_OUT_H
