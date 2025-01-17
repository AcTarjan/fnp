#ifndef FNP_TCP_API_H
#define FNP_TCP_API_H

#include "tcp_sock.h"


i32 tcp_send_mbuf(tcp_sock_t* sk, u8* buf, i32 len);

i32 tcp_recv(tcp_sock_t* sk, u8* buf, i32 len);

void tcp_close(tcp_sock_t* sk);

#endif //FNP_TCP_API_H
