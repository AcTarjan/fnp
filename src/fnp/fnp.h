#ifndef FNP_H
#define FNP_H

#include "fnp_sockaddr.h"

typedef void *FNP_SOCKET_TYPE;
typedef void *MBUF_TYPE;

typedef struct fnp_rate_measure
{
    i64 total;    // 字节数
    i64 last;     // 上次时间
    i64 interval; // 时间间隔
} fnp_rate_measure_t;

void fnp_compute_rate(fnp_rate_measure_t *meas, i64 size);

/*
 * fnp_init
 * 初始化fnp环境, 必须在启动fnp-daemon之后使用
 */
int fnp_init();

#define fnp_ipv4_ston(ip) ipv4_ston((ip));
#define fnp_ipv4_ntos(ip) ipv4_ntos((ip));

/* mbuf相关*/
MBUF_TYPE fnp_alloc_mbuf();

void fnp_free_mbuf(MBUF_TYPE m);

i32 fnp_get_mbuf_len(MBUF_TYPE m);

u8 *fnp_mbuf_data(MBUF_TYPE m);

void fnp_set_mbuf_len(MBUF_TYPE m, i32 len);

/*
 创建一个socket，全部为网络序
 proto: 协议类型, 取值: IPPROTO_TCP, IPPROTO_UDP
 lip, lport: 本地ip和端口号, 均为网络序
 rip, rport: 远端ip和端口号, 均为网络序
 对于tcp/udp server: 指定本地ip和端口号, 目标ip和端口号为0
 对于tcp client: 本地ip和端口号可以为0, 目标ip和端口号必须指定
 对于udp client: 本地ip和端口号可以为0, 目标ip和端口号也可以为0，调用sendto函数确定目标ip和端口号，处理过程会慢一些，最好指定目标ip和端口号
 */
FNP_SOCKET_TYPE fnp_create_socket(u8 proto, u32 lip, u16 lport, i32 opt);

/*
 * fnp_accept
 * 接收一个tcp连接
 * socketfd: a listen socket
 * 返回值: a new connection socket
 */
FNP_SOCKET_TYPE fnp_accept(FNP_SOCKET_TYPE socketfd);

/*
 * fnp_connect
 * tcp/udp socket连接到目标ip和端口号
 * socketfd: a tcp client socket
 * 返回值: 0表示成功, -1表示失败
 */
int fnp_connect(FNP_SOCKET_TYPE socketfd, u32 rip, u16 rport);

void fnp_close(FNP_SOCKET_TYPE socketfd);

// 用于已经确定目标ip和端口号的socket
int fnp_send(FNP_SOCKET_TYPE socketfd, MBUF_TYPE m);

// 用于未确定目标ip和端口号的socket
int fnp_sendto(FNP_SOCKET_TYPE socketfd, MBUF_TYPE m, faddr_t *raddr);

MBUF_TYPE fnp_recv(FNP_SOCKET_TYPE socketfd);

MBUF_TYPE fnp_recvfrom(FNP_SOCKET_TYPE socketfd, faddr_t *remote);

#endif // FNP_H
