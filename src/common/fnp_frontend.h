#ifndef FNP_FRONTEND_H
#define FNP_FRONTEND_H

#include "fnp_socket.h"
#include "fnp_list.h"
#include <rte_spinlock.h>

typedef struct fnp_frontend
{
    i32 pid;
    u16 alive : 1; // 是否存活
    u16 fail_cnt; // 没有接收到心跳包的次数
    fnp_list_node_t master_node; // 用于master使用链表管理前端
    rte_spinlock_t lock;
    int socket_num;
    fnp_list_t socket_list;
} fnp_frontend_t;


static inline void frontend_add_socket(fnp_frontend_t* frontend, fsocket_t* socket)
{
    socket->frontend_id = frontend->pid;

    rte_spinlock_lock(&frontend->lock);
    frontend->socket_num++;
    fnp_list_insert(&frontend->socket_list, &socket->frontend_node, socket);
    rte_spinlock_unlock(&frontend->lock);
}

static inline void frontend_remove_socket(fnp_frontend_t* frontend, fsocket_t* socket)
{
    socket->frontend_id = 0;

    rte_spinlock_lock(&frontend->lock);
    frontend->socket_num--;
    fnp_list_delete(&frontend->socket_list, &socket->frontend_node);
    rte_spinlock_unlock(&frontend->lock);
}


#endif // FNP_FRONTEND_H
