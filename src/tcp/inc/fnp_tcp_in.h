#ifndef FNP_FNP_TCP_IN_H
#define FNP_FNP_TCP_IN_H

#include <rte_tcp.h>
#include "fnp_tcp_sock.h"



void tcp_recv_mbuf(rte_mbuf* m);

void tcp_listen_recv(tcp_sock_t* sk, tcp_seg_t* seg);

void tcp_syn_sent_recv(tcp_sock_t* sk, tcp_seg_t* seg);

void tcp_syn_recv_recv(tcp_sock_t* sk, tcp_seg_t* seg);

void tcp_data_recv(tcp_sock_t* sk, tcp_seg_t* seg);

#endif //FNP_FNP_TCP_IN_H
