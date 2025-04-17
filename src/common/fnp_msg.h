#ifndef FNP_MSG_H
#define FNP_MSG_H

#include "fnp_sockaddr.h"

typedef enum fnp_msg_role
{
    fmsg_role_unknown = 0,
    fmsg_role_master,
    fmsg_role_worker,
    fmsg_role_frontend,
} fmsg_role_t;

typedef enum fnp_msg_type
{
    fmsg_type_unknown = 0,
    fmsg_type_register_frontend, //注册前端, frontend -> master
    fmsg_type_create_socket, //创建socket, frontend -> master
    fmsg_type_add_socket, //向worker中添加socket, master -> worker
    fmsg_type_create_cnx, //创建quic cnx, frontend -> worker
    fmsg_type_create_stream, //创建quic stream, frontend -> worker
} fmsg_type_t;

typedef struct create_socket_param
{
    fnp_protocol_t proto;
    fsockaddr_t local;
    fsockaddr_t remote;
    void* conf;
} create_socket_param_t;

typedef struct create_quic_cnx_param
{
    void* quic;
    fsockaddr_t remote;
} create_quic_cnx_param_t;

typedef struct create_stream_param
{
    void* cnx;
    bool is_unidir;
    int priority;
} create_stream_param_t;


typedef struct fmsg_listener
{
    int id;
    int epfd; // epoll fd
    int efd; // event fd
    struct rte_ring* ring; //多进程写,单进程写
} fmsg_listener_t;

#define fnp_master_id 8

typedef struct fnp_msg
{
    bool is_reply; //是否是响应, 响应和请求共用一个fmsg. 发送端会检查该字段来接收响应.
    int code; //返回码, 仅响应有效
    int src_id;
    fmsg_type_t type;
    void* ptr;
    u8 data[128];
} fnp_msg_t;

typedef void (*fmsg_handler_func)(fnp_msg_t*);

int init_fmsg_center();

fnp_msg_t* new_fmsg(i32 src_id, fmsg_type_t type);

fmsg_listener_t* register_fmsg_listener(i32 id);

int send_fmsg(int dst_id, fnp_msg_t* msg);

int send_fmsg_with_reply(int dst_id, fnp_msg_t* msg);

void send_fmsg_reply(fnp_msg_t* msg);

void fmsg_listener_wait(fmsg_listener_t* listener, fmsg_handler_func handler);

#endif //FNP_MSG_H
