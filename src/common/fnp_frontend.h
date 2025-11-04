#ifndef FNP_FRONTEND_H
#define FNP_FRONTEND_H

#include <rte_spinlock.h>

#include "fnp_socket.h"
#include "fnp_list.h"
#include "fnp_msg.h"

#define FNP_FRONTEND_MAX_FDS 128

typedef struct fnp_frontend
{
    // 对于多进程来说，不同进程的efd是不同的
    fsocket_t* fd_table[FNP_FRONTEND_MAX_FDS]; // 通过eventfd查找fsocket
    struct rte_mbuf* recv_mbufs[FNP_FRONTEND_MAX_FDS][RECV_BATCH_SIZE];

    struct
    {
        int index;
        int total;
    } recv_mbufs_counter[FNP_FRONTEND_MAX_FDS];

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
    if (frontend->pool != NULL)
    {
        // 后端释放
        rte_mempool_free(frontend->pool);
    }
    fnp_free(frontend);
}

#endif // FNP_FRONTEND_H
