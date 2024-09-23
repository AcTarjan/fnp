#ifndef FNP_H
#define FNP_H
#include <stdint.h>
#include "fnp_common.h"
/*
 * fnp_init
 * 初始化fnp, 必须在使用fnp之前调用
*/
int32_t fnp_init(uint8_t * path);

void* fnp_tcp_sock(uint32_t id, uint16_t port, uint32_t rip, uint16_t rport);

/*
 * fnp_tcp_listen
 * 监听网卡的TCP端口
 * id: 网卡id
 * port: 本地端口号, 主机序
 * 返回值: a listen socket
 */
void* fnp_tcp_listen(uint32_t id, uint16_t port);

/*
 * fnp_tcp_accept
 * 接收一个tcp连接
 * sock: a listen socket
 * 返回值: a new connection socket
 */
void* fnp_tcp_accept(void* sock);

/*
 * fnp_tcp_connect
 * 连接到TCP Server
 * id: 网卡id
 * port: 本地端口号, 主机序, 0表示随机端口
 * rip: 目标ip地址, 网络序
 * rport: 目标端口号, 网络序
 * 返回值:  a connection socket
 */
void* fnp_tcp_connect(uint16_t id, uint16_t port, uint32_t rip, uint16_t rport);

/*
 * fnp_tcp_send
 * 发送数据
 * sock: an connection socket
 * buf: 数据缓冲区
 * len: 数据长度
 * 返回值: 成功发送的数据长度
 */
int32_t fnp_tcp_send(void* sock, uint8_t* buf, int32_t len);

/*
 * fnp_tcp_recv
 * 接收数据
 * sock: an connection socket
 * buf: 数据缓冲区
 * len: 数据长度
 * 返回值: 成功接收的数据长度
 */
int32_t fnp_tcp_recv(void* sock, uint8_t* buf, int32_t len);

/*
 * fnp_tcp_close
 * 关闭listen socket 或者 connection socket
 * sock: socket指针
 */
void fnp_tcp_close(void* sock);


#endif //FNP_H
