#ifndef FNP_H
#define FNP_H
#include "rte_mbuf.h"


/*
 * fnp_init
 * 初始化fnp环境, 必须在启动fnp-daemon之后使用
*/
int fnp_init();


uint32_t fnp_ipv4_ston(const char* ip);

char* fnp_ipv4_ntos(uint32_t ip);

/*
 创建一个socket，全部为网络序
 proto: 协议类型, 取值: IPPROTO_TCP, IPPROTO_UDP
 对于tcp server: 指定本地ip和端口号, 目标ip和端口号为0
 对于tcp client: 本地ip和端口号可以为0, 目标ip和端口号为指定值
 对于udp server: 本地ip和端口号必须设置，
 对于udp client: 本地ip和端口号可以为0, 目标ip和端口号也可以为0，在发送时指定目标ip和端口号
 */
void* fnp_socket(uint8_t proto, uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport);


/* fnp_bind
 * 为socket绑定ip和端口号，检测端口是否被占用
 * 必须bind后才能使用
 * socket: a socket
 * reuse: 是否允许端口复用, 0表示不允许端口复用, 1表示允许端口复用，暂不支持
 * 返回值: 0表示成功, -1表示失败
 */
int fnp_bind(void* socket, int reuse);

struct rte_mbuf* fnp_alloc_mbuf();

/*
 * fnp_listen
 * tcp socket进入监听状态
 * socketfd: a tcp server socket
 * 返回值: 0表示成功, -1表示失败
 */
int fnp_listen(void* socketfd);

/*
 * fnp_accept
 * 接收一个tcp连接
 * socketfd: a listen socket
 * 返回值: a new connection socket
 */
void* fnp_accept(void* socketfd);

/*
 * fnp_connect
 * tcp socket连接到目标ip和端口号
 * socketfd: a tcp client socket
 * 返回值: 0表示成功, -1表示失败
 */
int fnp_connect(void* socketfd);



int fnp_send(void* socketfd, struct rte_mbuf* m);

struct rte_mbuf* fnp_recv(void* socketfd);


#endif //FNP_H
