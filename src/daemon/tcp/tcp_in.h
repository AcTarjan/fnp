#ifndef FNP_TCP_IN_H
#define FNP_TCP_IN_H

#include "tcp_sock.h"

typedef void (*tcp_recv_func)(tcp_sock_t *sock, tcp_segment *seg);

void tcp_listen_recv(tcp_sock_t *sock, tcp_segment *seg);

void tcp_synsent_recv(tcp_sock_t *sock, tcp_segment *seg);

void tcp_synrecv_recv(tcp_sock_t *sock, tcp_segment *seg);

void tcp_estab_recv(tcp_sock_t *sock, tcp_segment *seg);

void tcp_closed_recv(tcp_sock_t *sock, tcp_segment *seg);

#endif // FNP_TCP_IN_H
