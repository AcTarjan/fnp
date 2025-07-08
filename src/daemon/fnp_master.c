#include "fnp_frontend.h"

#include <unistd.h>

#include "fnp_common.h"
#include "fnp_error.h"
#include "fnp_context.h"
#include "fnp_msg.h"
#include "fnp_worker.h"
#include "hash.h"
#include "quic.h"
#include "udp.h"
#include "tcp.h"

#include <sys/timerfd.h>

static fnp_list_t frontend_list;

static int compare_pid(fnp_frontend_t* a, fnp_frontend_t* b)
{
    return a->pid - b->pid;
}

// 控制线程调用
static int handle_register_fmsg(fnp_msg_t* msg)
{
    FNP_INFO("start to register frontend from %d\n", msg->src_id);

    fnp_frontend_t* frontend = msg->ptr;
    if (frontend == NULL)
        return FNP_ERR_NO_FRONTEND;

    if (fnp_list_find(&frontend_list, frontend))
    {
        return FNP_ERR_FRONTEND_REGISTERED;
    }

    // 注册前端
    fnp_list_insert(&frontend_list, &frontend->master_node, frontend);

    FNP_INFO("register frontend %d successfully\n", frontend->pid);
    return FNP_OK;
}

// main lcore调用，检查fnp-frontend是否正常
// daemon的控制线程添加frontendTbl
static void check_frontend_alive()
{
    fnp_list_node_t* node = fnp_list_first(&frontend_list);
    while (node != NULL)
    {
        fnp_frontend_t* frontend = node->value;
        fnp_list_node_t* next_node = fnp_list_get_next(node);
        if (frontend->alive)
        {
            frontend->alive = 0;
            frontend->fail_cnt = 0;
        }
        else
        {
            frontend->fail_cnt++;
            if (frontend->fail_cnt > 3)
            {
                FNP_INFO("frontend %d fail to keepalive, start to delete!!!\n", frontend->pid);
                // 从master删除该前端
                fnp_list_delete(&frontend_list, node);

                // 释放该前端所有的socket
                fnp_list_node_t* socket_node = fnp_list_first(&frontend->socket_list);
                while (socket_node != NULL)
                {
                    fsocket_t* socket = socket_node->value;
                    fnp_list_node_t* next_socket_node = fnp_list_get_next(socket_node);
                    if (socket->worker_id == FNP_MAX_WORKER_NUM) //worker中不包含这种类型的socket, 直接释放
                    {
                        free_fsocket(socket);
                    }
                    else
                    {
                        socket->request_close = 1; // 请求关闭socket, worker执行释放
                    }

                    socket_node = next_socket_node;
                }

                // 删除该前端
                fnp_free(frontend);
            }
        }
        node = next_node;
    }
}

static void handle_create_socket_fmsg(fnp_msg_t* msg)
{
    create_socket_param_t* param = msg->data;
    fsocket_t* socket = create_fsocket(param->proto, &param->local, &param->remote, param->conf, -1);
    if (socket == NULL)
    {
        msg->code = FNP_ERR_CREATE_SOCKET;
    }
    else
    {
        msg->code = FNP_OK;
        msg->ptr = socket;
    }

    send_fmsg_reply(msg);
}

static void handle_master_fmsg(fnp_msg_t* msg)
{
    switch (msg->type)
    {
    case fmsg_type_create_socket:
        {
            handle_create_socket_fmsg(msg);
            break;
        }
    case fmsg_type_register_frontend:
        {
            int ret = handle_register_fmsg(msg);
            msg->code = ret;
            send_fmsg_reply(msg);
            break;
        }
    }
}

int create_timerfd(int timeout, bool periodic)
{
    int timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timerfd == -1)
    {
        perror("timerfd_create");
        return -1;
    }

    struct itimerspec new_value = {0};
    struct itimerspec old_value; // 可选，用于获取旧的定时器设置

    // 设置首次超时时间 (例如：5秒后)
    new_value.it_value.tv_sec = timeout;
    new_value.it_value.tv_nsec = 0;

    // 设置周期性超时时间 (例如：之后每1秒超时一次)
    // 如果设置为0，则为一次性定时器
    if (periodic)
    {
        new_value.it_interval.tv_sec = timeout;
        new_value.it_interval.tv_nsec = 0;
    }

    if (timerfd_settime(timerfd, 0, &new_value, &old_value) == -1)
    {
        perror("timerfd_settime");
        // 错误处理
    }

    return timerfd;
}

/*
 * master控制线程:
 * 1. 负责frontend注册
 * 2. 检查frontend的状态, 删除丢失心跳的frontend, 并释放其资源
 */
static void handle_master_fmsg_loop()
{
    printf("start task to manage frontend\n");

    fmsg_listener_t* listener = register_fmsg_listener(fnp_master_id);
    if (listener == NULL)
    {
        printf("controller register fmsg_listener failed\n");
        return;
    }

    int timerfd = create_timerfd(5, true);
    int epfd = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET; // 监听可读事件，通常使用边缘触发
    ev.data.fd = timerfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, timerfd, &ev) == -1)
    {
        perror("epoll_ctl: timerfd");
        // 错误处理
    }

#define MAX_EVENTS 4
    struct epoll_event evs[MAX_EVENTS];

    while (1)
    {
        int n = epoll_wait(epfd, evs, MAX_EVENTS, 0);
        for (int i = 0; i < n; i++)
        {
            if (evs[i].data.fd == timerfd)
            {
                uint64_t expirations;
                read(timerfd, &expirations, sizeof(expirations)); //清除定时器计数
                check_frontend_alive();
            }
        }
        fmsg_listener_wait(listener, handle_master_fmsg);
    }
}

int init_fnp_master()
{
    fnp_init_list(&frontend_list, compare_pid);

    fnp.sockTbl = create_socket_table();
    if (fnp.sockTbl == NULL)
    {
        return FNP_ERR_CREATE_HASH_TABLE;
    }

    pthread_t ctrl_thread;
    int ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_master_task", NULL,
                                     handle_master_fmsg_loop, NULL);
    if (ret != 0)
    {
        RTE_LOG(ERR, EAL, "Failed to create control thread\n");
        return ret;
    }

    return FNP_OK;
}
