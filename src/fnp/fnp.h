#ifndef FNP_H
#define FNP_H

#include "fnp_sockaddr.h"
#include "fnp_quic_common.h"
#include "fnp_socket.h"

typedef void* fnp_mbuf_t;
typedef void* fnp_quic_cnx_t;


/*
 * fnp_init
 * 初始化fnp环境, 必须在启动fnp-daemon之后使用
 */
int fnp_init();

#define fnp_ipv4_ston(ip) ipv4_ston((ip));
#define fnp_ipv4_ntos(ip) ipv4_ntos((ip));

/* fnp_mbuf相关API接口 */
fnp_mbuf_t fnp_alloc_mbuf(fsocket_t* socketfd);

void fnp_free_mbuf(fnp_mbuf_t m);

i32 fnp_get_mbuf_len(fnp_mbuf_t m);

u8* fnp_mbuf_data(fnp_mbuf_t m);

void fnp_set_mbuf_len(fnp_mbuf_t m, i32 len);

int fsockaddr_init(fsockaddr_t* addr, int family, const char* ip, int port);

/*
 创建一个socket，全部为网络序
 proto: 协议类型, 取值: IPPROTO_TCP, IPPROTO_UDP
 lip, lport: 本地ip和端口号, 均为网络序
 rip, rport: 远端ip和端口号, 均为网络序
 对于tcp/udp server: 指定本地ip和端口号, 目标ip和端口号为0
 对于tcp client: 本地ip和端口号可以为0, 目标ip和端口号必须指定
 对于udp client: 本地ip和端口号可以为0, 目标ip和端口号也可以为0，调用sendto函数确定目标ip和端口号，处理过程会慢一些，最好指定目标ip和端口号
 */
fsocket_t* fnp_create_socket(fnp_protocol_t proto, const fsockaddr_t* local, const fsockaddr_t* remote, void* conf);


// 关闭socket
void fnp_close(fsocket_t* socket);


/*
 * fnp_connect
 * tcp/udp socket连接到目标ip和端口号
 * socketfd: a tcp client socket
 * 返回值: 0表示成功, -1表示失败
 */
int fnp_connect(fsocket_t* socket);

/*
 * fnp_accept
 * 接收一个tcp连接
 * socketfd: a listen socket
 * 返回值: a new connection socket
 */
fsocket_t* fnp_accept(fsocket_t* socket);


// 用于已经确定目标ip和端口号的socket
int fnp_send(fsocket_t* socket, fnp_mbuf_t m);

// 用于未确定目标ip和端口号的socket
int fnp_sendto(fsocket_t* socket, fnp_mbuf_t m, fsockaddr_t* raddr);

// 可以通过fmbuf_info获取数据包的信息
fnp_mbuf_t fnp_recv(fsocket_t* socket);


/* fnp_quic相关API接口 */
fnp_quic_config_t* fnp_get_quic_config();

fnp_quic_cnx_t fnp_quic_create_cnx(fsocket_t* quic, fsockaddr_t* remote);

fnp_quic_stream_t* fnp_quic_create_stream(fnp_quic_cnx_t cnx, bool is_unidir, int priority);

fnp_quic_cnx_t fnp_quic_accept_cnx(fsocket_t* quic);

fnp_quic_stream_t* fnp_quic_accept_stream(fnp_quic_cnx_t cnx);

int fnp_quic_send_stream_data(fnp_quic_stream_t* stream, fnp_mbuf_t m, bool fin);

fnp_mbuf_t fnp_quic_recv_stream_data(fnp_quic_stream_t* stream);


typedef struct fnp_rate_measure
{
    i64 total; // 字节数
    i64 last; // 上次时间
    i64 interval; // 时间间隔
} fnp_rate_measure_t;

void fnp_compute_rate(fnp_rate_measure_t* meas, i64 size);

#endif // FNP_H
