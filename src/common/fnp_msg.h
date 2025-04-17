#ifndef FNP_MSG_H
#define FNP_MSG_H

#include "fnp_socket.h"

#define FNP_MSG_NAME_REGISTER "register_msg"
#define FNP_MSG_NAME_KEEPALIVE_REQ "keepalive_req_msg"
#define FNP_MSG_NAME_KEEPALIVE_RESP "keepalive_resp_msg"
#define FNP_MSG_NAME_CREATE_SOCKET "create_socket_msg"
#define FNP_MSG_NAME_SOCKET_CONNECT "socket_connect_msg"

typedef struct register_req
{
    i32 pid; // 进程id
} register_req_t;

typedef struct register_reply
{
    i32 code;
} register_reply_t;

typedef struct create_socket_req
{
    fsockaddr_t addr;
    i32 opt;
} create_socket_req_t;

typedef struct create_socket_reply
{
    i32 code;
    fsocket_t *socket;
} create_socket_reply_t;

typedef struct socket_connect_req
{
    fsocket_t *socket;
    u32 rip;
    u16 rport;
} socket_connect_req_t;

typedef struct socket_connect_reply
{
    i32 code;
} socket_connect_reply_t;

int init_msg_layer();

#endif // FNP_MSG_H
