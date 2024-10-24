#ifndef FNP_TCP_API_H
#define FNP_TCP_API_H

#include "tcp_sock.h"


tcp_sock* tcp_listen(sock_param* param);

tcp_sock* tcp_accept(tcp_sock* sk);

tcp_sock* tcp_connect(sock_param* param);

i32 tcp_send(tcp_sock* sk, u8* buf, i32 len);

i32 tcp_recv(tcp_sock* sk, u8* buf, i32 len);

void tcp_close(tcp_sock* sk);

#endif //FNP_TCP_API_H
