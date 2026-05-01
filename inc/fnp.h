#ifndef FNP_H
#define FNP_H

#include "fnp_common.h"
#include "fnp_config.h"
#include "fnp_sockaddr.h"
#include "fnp_mbuf.h"

typedef struct fnp_socket fnp_socket_t;

typedef void (*fnp_handler_func)(fnp_socket_t *socket, fnp_mbuf_t *m, void *arg);
typedef int (*fnp_lcore_func_t)(void *arg);

#define FNP_INIT_NETWORK_REQ_MAX 8
#define FNP_INIT_IFADDR_MAX 32
#define FNP_NETWORK_NAME_LEN 32
#define FNP_IFADDR_NAME_LEN 32
#define FNP_DEVICE_NAME_LEN 32
#define FNP_SERVICE_NAME_LEN 32

typedef struct fnp_network_request
{
  char network_name[FNP_NETWORK_NAME_LEN];
  u16 ip_count;
  u16 reserved0;
} fnp_network_request_t;

typedef struct fnp_ifaddr_info
{
  u16 id;
  u16 network_id;
  u16 device_id;
  u8 prefix_len;
  u8 reserved0;
  char network_name[FNP_NETWORK_NAME_LEN];
  char name[FNP_IFADDR_NAME_LEN];
  char device_name[FNP_DEVICE_NAME_LEN];
  u32 ip;
  u32 gateway;
} fnp_ifaddr_info_t;

typedef struct fnp_init_conf
{
  int main_lcore;
  int *lcores;
  int num_lcores;
  u16 id;
  u16 reserved0;
  char name[FNP_SERVICE_NAME_LEN];
} fnp_init_conf_t;

/*
 * fnp_init
 * 初始化 fnp 环境并向 daemon 注册 frontend。
 */
int fnp_init(fnp_init_conf_t *conf);

const fnp_ifaddr_info_t *fnp_get_ifaddrs(u16 *ifaddr_count);

#define FNP_GTPU_UDP_PORT 2152

typedef struct fnp_gtpu_socket_conf
{
  fsockaddr_t local;  // 隧道本地接收地址，网络序；port 为 0 时默认使用 2152
  fsockaddr_t remote; // 隧道对端接收地址，网络序；port 为 0 时默认使用 2152
  u32 incoming_teid;  // 收包匹配使用，主机序
  u32 outgoing_teid;  // 发包封装使用，主机序
} fnp_gtpu_socket_conf_t;

/*
 创建一个socket，全部为网络序
 type: 当前仅支持 fsocket_type_gtpu
 conf:
   GTP-U: 传 fnp_gtpu_socket_conf_t*
 out:
   返回对应用层可见的fnp_socket_t句柄
 */
int fnp_socket_create(fsocket_type_t type, const void *conf, fnp_socket_t **out);

int fnp_socket_get_conf(const fnp_socket_t *socket, void *conf, u16 *conf_len);

int fnp_socket_close(fnp_socket_t *socket);

int fnp_socket_send(fnp_socket_t *socket, fnp_mbuf_t *m);

int fnp_socket_recvfrom(fnp_socket_t *socket, uint8_t *buf, int buf_len, fsockaddr_t *peer);

int fnp_socket_recv(fnp_socket_t *socket, uint8_t *buf, int buf_len);

int fnp_socket_recv_mbuf(fnp_socket_t *socket, fnp_mbuf_t **m);

int fnp_socket_recv_mbuf_burst(fnp_socket_t *socket, fnp_mbuf_t **mbufs, u32 count);

int fnp_epoll_create(void);

int fnp_epoll_add(int epfd, fnp_socket_t *socket, fnp_handler_func handler, void *arg);

int fnp_epoll_del(int epfd, fnp_socket_t *socket);

int fnp_epoll_wait(int epfd, int timeout_ms, int budget);

void fnp_epoll_destroy(int epfd);

int fnp_polling(fnp_socket_t *socket, fnp_handler_func handler, void *arg);

int fnp_lcore_launch(unsigned lcore_id, fnp_lcore_func_t func, void *arg);

int fnp_lcore_wait(unsigned lcore_id);

unsigned fnp_lcore_id(void);

#endif // FNP_H
