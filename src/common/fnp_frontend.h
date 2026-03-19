#ifndef FNP_FRONTEND_H
#define FNP_FRONTEND_H

#include <rte_spinlock.h>

#include "fnp_socket.h"
#include "fnp_list.h"
#include "fnp_msg.h"

#define FNP_FRONTEND_INITIAL_FDS 64

typedef struct fnp_frontend
{
    fsocket_t** sockets; // 共享fsocket数组，仅供daemon在frontend崩溃时清理
    u32 socket_capacity;

    struct rte_mempool* pool; //后端为前端分配的内存池


    i32 pid;
    u16 alive : 1; // 是否存活
    u16 fail_cnt; // 没有接收到心跳包的次数
    fnp_list_node_t master_node; // 用于master使用链表管理前端
    rte_spinlock_t lock;
    i32 socket_num;
} fnp_frontend_t;


static inline void frontend_free(fnp_frontend_t* frontend)
{
    fnp_free(frontend->sockets);
    fnp_free(frontend);
}

#endif // FNP_FRONTEND_H
