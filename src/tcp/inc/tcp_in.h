#ifndef FNP_TCP_IN_H
#define FNP_TCP_IN_H

#include <rte_tcp.h>
#include "tcp_sock.h"




void tcp_LISTEN_recv(tcp_sock* sk, tcp_segment* seg);

void tcp_SYN_SENT_recv(tcp_sock* sk, tcp_segment* seg);

void tcp_SYN_RECV_recv(tcp_sock* sk, tcp_segment* seg);

void tcp_ESTAB_data(tcp_sock* sk, tcp_segment* seg);

#endif //FNP_TCP_IN_H
