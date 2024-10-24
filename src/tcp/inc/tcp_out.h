#ifndef FNP_TCP_OUT_H
#define FNP_TCP_OUT_H

#include "tcp_sock.h"

typedef void (*tcp_send_func)(tcp_sock* sk);

void tcp_send_ack(tcp_sock* sk, bool delay);

void tcp_send_rst(tcp_segment* seg);

void tcp_data_send(tcp_sock* sk);

void tcp_syn_send(tcp_sock* sk);

void tcp_listen_send(tcp_sock* sk);

void tcp_closed_send(tcp_sock* sk);

#endif //FNP_TCP_OUT_H
