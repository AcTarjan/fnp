#ifndef FNP_H
#define FNP_H

/*
 * fnp_init
 * 初始化fnp
*/
int fnp_init(u8* path);

void* fnp_tcp_sock(u32 lip, u16 lport, u32 rip, u16 rport);

void* fnp_tcp_listen(u32 lip, u16 lport);

void* fnp_tcp_accept(void* sock);

i32 fnp_tcp_connect(void* sock);

i32 fnp_tcp_send(void* sock, u8* buf, i32 len);

i32 fnp_tcp_recv(void* sock, u8* buf, i32 len);

void fnp_tcp_close(void* sock);

#endif //FNP_H
