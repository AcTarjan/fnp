#ifndef FNP_H
#define FNP_H

#include "fnp_config.h"
#include "fnp_sockaddr.h"
#include "fnp_mbuf.h"

/*
 * fnp_init
 * 初始化fnp环境, 必须在启动fnp-daemon之后使用
 * main_lcore: 主线程的lcore id, 一般设置为0
 * lcores: 用于指定哪些lcore可以处理用户任务, 可以为空
 */
int fnp_init(int main_lcore, int lcores[], int num_lcores);

/*
 创建一个socket，全部为网络序
 proto: 协议类型, 取值: IPPROTO_TCP, IPPROTO_UDP
 lip, lport: 本地ip和端口号, 均为网络序
 rip, rport: 远端ip和端口号, 均为网络序
 对于tcp/udp server: 指定本地ip和端口号, 目标ip和端口号为0
 对于tcp client: 本地ip和端口号可以为0, 目标ip和端口号必须指定
 对于udp client: 本地ip和端口号可以为0, 目标ip和端口号也可以为0，调用sendto函数确定目标ip和端口号，处理过程会慢一些，最好指定目标ip和端口号
 */
int fnp_create_socket(fnp_protocol_t proto, const fsockaddr_t* local, const fsockaddr_t* remote, void* conf);


// 关闭socket
void fnp_close(int fd);

/*
 * fnp_accept
 * 接收一个tcp连接
 * socketfd: a listen socket
 * 返回值: a new connection socket
 */
int fnp_accept(int server_fd);


// 用于已经确定目标ip和端口号的socket
int fnp_send(int fd, fnp_mbuf_t* m);

// 用于未确定目标ip和端口号的socket
int fnp_sendto(int fd, fnp_mbuf_t* m, fsockaddr_t* raddr);

// 可以通过fmbuf_info获取数据包的信息
int fnp_recv(int fd, fnp_mbuf_t** m);


/* fnp_quic相关API接口 */
fnp_quic_config_t* fnp_get_quic_config();

// fsocket_t* fnp_quic_create_cnx(fsocket_t* quic, fsockaddr_t* remote);
//
// fnp_quic_stream_t* fnp_quic_create_stream(fsocket_t* cnx, bool is_unidir, int priority);
//
// fsocket_t* fnp_quic_accept_cnx(fsocket_t* quic);
//
// fnp_quic_stream_t* fnp_quic_accept_stream(fsocket_t* cnx);
//
// int fnp_quic_stream_send(fnp_quic_stream_t* stream, fnp_mbuf_t* m, bool fin);
//
// fnp_mbuf_t* fnp_quic_recv_stream_data(fnp_quic_stream_t* stream);

#endif // FNP_H
