#ifndef FNP_MSG_H
#define FNP_MSG_H

#include <rte_epoll.h>
#include <unistd.h>

#include "fnp_sockaddr.h"
#include "fnp_ring.h"

#include <sys/epoll.h>

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
    fmsg_type_connect_fsocket, // master -> worker, 建立tcp连接
    fmsg_type_close_fsocket, // master -> worker, 关闭tcp连接
    fmsg_type_free_socket, //worker -> master, 释放socket
    fmsg_type_create_cnx, //创建quic cnx, frontend -> worker
    fmsg_type_create_stream, //创建quic stream, frontend -> worker
} fmsg_type_t;

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


typedef struct fnp_channel
{
    fnp_ring_t* ring; //多进程写,单进程读
    int event_fd; // event fd
} fchannel_t;

void fchannel_init(fchannel_t* chan, int efd, fnp_ring_t* ring);

fchannel_t* fchannel_create(i32 size);

bool fchannel_enqueue(fchannel_t* chan, void* data);

void fchannel_free(fchannel_t* chan);

typedef struct fnp_msg
{
    bool is_reply; //是否是响应, 响应和请求共用一个fmsg. 发送端会检查该字段来接收响应.
    int code; //返回码, 仅响应有效
    int src_id;
    fmsg_type_t type;
    void* ptr;
    u8 data[128];
} fnp_msg_t;

// fnp epoll
static inline int fmsg_epoll_create()
{
    return epoll_create1(0);
};

static inline int fmsg_epoll_add(int epfd, int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;

    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline void fmsg_epoll_del(int epfd, int op, int fd)
{
    (void)op;
    epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

static inline void fmsg_epoll_close(int epfd)
{
    close(epfd);
}

typedef void (*fmsg_handler_func)(fnp_msg_t*);
void fchannel_handle(fchannel_t* chan, fmsg_handler_func handler);

fnp_msg_t* fmsg_new(fmsg_type_t type);

int fmsg_send(fchannel_t* chan, fnp_msg_t* msg);

int fmsg_send_with_reply(fchannel_t* chan, fnp_msg_t* msg);

void fmsg_send_reply(fnp_msg_t* msg);

int fnp_create_timerfd(int timeout, bool periodic);

#endif //FNP_MSG_H
