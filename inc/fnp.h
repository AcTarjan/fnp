#ifndef FNP_H
#define FNP_H

#include "fnp_config.h"
#include "fnp_sockaddr.h"
#include "fnp_mbuf.h"

typedef struct fnp_socket fnp_socket_t;

typedef int (*fnp_handler_func)(fnp_socket_t* socket, fnp_mbuf_t* m, void* arg);
typedef int (*fnp_lcore_func_t)(void* arg);

/*
 * fnp_init
 * 初始化fnp环境, 必须在启动fnp-daemon之后使用
 * main_lcore: 主线程的lcore id, 一般设置为0
 * lcores: 用于指定哪些lcore可以处理用户任务, 可以为空
 */
int fnp_init(int main_lcore, int lcores[], int num_lcores);

typedef struct fnp_udp_socket_conf
{
    fsockaddr_t local;  // 网络序
    fsockaddr_t remote; // 网络序
} fnp_udp_socket_conf_t;

typedef struct fnp_tcp_socket_conf
{
    fsockaddr_t local;  // 网络序
    fsockaddr_t remote; // 网络序
    u32 reserved0;      // 预留扩展，当前未使用
} fnp_tcp_socket_conf_t;

typedef struct fnp_raw_socket_conf
{
    u8 protocol; // IPPROTO_*，0表示不按协议号过滤，仅按local_ip匹配
    u8 reserved0;
    u16 device_id;
    u32 local_ip; // 网络序，0表示不按本地IP过滤，仅按protocol匹配
} fnp_raw_socket_conf_t;

/*
 创建一个socket，全部为网络序
 type: socket类型, 取值: fsocket_type_udp / fsocket_type_tcp / fsocket_type_raw
 conf:
   UDP: 传 fnp_udp_socket_conf_t*
   TCP: 传 fnp_tcp_socket_conf_t*
   RAW: 传 fnp_raw_socket_conf_t*，protocol和local_ip至少要指定一个
 out:
   返回对应用层可见的fnp_socket_t句柄
 */
int fnp_socket_create(fsocket_type_t type, const void* conf, fnp_socket_t** out);

int fnp_socket_close(fnp_socket_t* socket);

int fnp_socket_send(fnp_socket_t* socket, fnp_mbuf_t* m);

int fnp_socket_sendto(fnp_socket_t* socket, fnp_mbuf_t* m, const fsockaddr_t* peer);

int fnp_socket_recvfrom(fnp_socket_t* socket, uint8_t* buf, int buf_len, fsockaddr_t* peer);

int fnp_socket_recv(fnp_socket_t* socket, uint8_t* buf, int buf_len);

int fnp_epoll_create(void);

int fnp_epoll_add(int epfd, fnp_socket_t* socket, fnp_handler_func handler, void* arg);

int fnp_epoll_del(int epfd, fnp_socket_t* socket);

int fnp_epoll_wait(int epfd, int timeout_ms, int budget);

void fnp_epoll_destroy(int epfd);

int fnp_lcore_launch(unsigned lcore_id, fnp_lcore_func_t func, void* arg);

int fnp_lcore_wait(unsigned lcore_id);

unsigned fnp_lcore_id(void);


/* fnp_quic相关API接口 */
fnp_quic_config_t* fnp_get_quic_config();

// fnp_socket_t* fnp_quic_create_cnx(fnp_socket_t* quic, fsockaddr_t* remote);
//
// fnp_quic_stream_t* fnp_quic_create_stream(fnp_socket_t* cnx, bool is_unidir, int priority);
//
// fnp_socket_t* fnp_quic_accept_cnx(fnp_socket_t* quic);
//
// fnp_quic_stream_t* fnp_quic_accept_stream(fnp_socket_t* cnx);
//
// int fnp_quic_stream_send(fnp_quic_stream_t* stream, fnp_mbuf_t* m, bool fin);
//
// fnp_mbuf_t* fnp_quic_recv_stream_data(fnp_quic_stream_t* stream);

#endif // FNP_H
