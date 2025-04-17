#include "fnp_msg.h"

#include <unistd.h>
#include <sys/eventfd.h>

#include "hash.h"
#include "fnp_error.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>

#define MAX_LISTENERS 8

// 数组长度为10
static fmsg_listener_t** listeners = NULL;
// id 对于worker_id

#define FMSG_CENTER_TABLE_NAME "fmsg_center"

int init_fmsg_center()
{
    if (rte_eal_process_type() == RTE_PROC_PRIMARY)
    {
        const struct rte_memzone* mz = rte_memzone_reserve(
            FMSG_CENTER_TABLE_NAME, // 唯一标识符，其他进程通过此名称查找
            sizeof(fmsg_listener_t*) * MAX_LISTENERS, // 数组大小
            SOCKET_ID_ANY, // NUMA节点（任意）
            RTE_MEMZONE_IOVA_CONTIG // 确保物理地址连续（可选）
        );
        if (mz == NULL)
            rte_exit(EXIT_FAILURE, "Failed to reserve memzone\n");
        listeners = mz->addr;
    }
    else
    {
        const struct rte_memzone* mz = rte_memzone_lookup(FMSG_CENTER_TABLE_NAME);
        if (mz == NULL)
            rte_exit(EXIT_FAILURE, "Shared array not found\n");
        listeners = mz->addr;
    }

    return FNP_OK;
}

fnp_msg_t* new_fmsg(i32 src_id, fmsg_type_t type)
{
    fnp_msg_t* msg = fnp_malloc(sizeof(fnp_msg_t));
    if (msg == NULL)
    {
        return NULL;
    }

    msg->src_id = src_id;
    msg->type = type;
    msg->is_reply = false;
    return msg;
}

fmsg_listener_t* register_fmsg_listener(i32 id)
{
    fmsg_listener_t* p = fnp_malloc(sizeof(fmsg_listener_t));

    p->id = id;
    p->epfd = epoll_create1(0);
    p->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    char ring_name[32];
    sprintf(ring_name, "fmsg_listener_%d", id);
    p->ring = rte_ring_create(ring_name, 64,
                              rte_socket_id(), RING_F_MP_HTS_ENQ | RING_F_SC_DEQ);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = p->efd;
    ev.data.ptr = p;
    epoll_ctl(p->epfd, EPOLL_CTL_ADD, p->efd, &ev);

    listeners[id] = p;

    return p;
}

int send_fmsg(int dst_id, fnp_msg_t* msg)
{
    fmsg_listener_t* p = listeners[dst_id];

    rte_ring_mp_enqueue(p->ring, msg);


    return FNP_OK;
}

int send_fmsg_with_reply(int dst_id, fnp_msg_t* msg)
{
    fmsg_listener_t* listener = listeners[dst_id];

    rte_ring_mp_enqueue(listener->ring, msg);

    //TODO: 设置超时
    while (!msg->is_reply);
    if (msg->code < 0)
    {
        fnp_free(msg);
        return msg->code;
    }

    return FNP_OK;
}


void send_fmsg_reply(fnp_msg_t* msg)
{
    msg->is_reply = true;
}

void fmsg_listener_wait(fmsg_listener_t* listener, fmsg_handler_func handler)
{
    fnp_msg_t* msg = NULL;
    while (rte_ring_sc_dequeue(listener->ring, (void**)&msg) == 0)
    {
        handler(msg);
    }
}


int fmsg_listener_add_event(fmsg_listener_t* listener, int fd)
{
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;

    epoll_ctl(listener->epfd, EPOLL_CTL_ADD, fd, &ev);

    return FNP_OK;
}


void fmsg_listener_del_event(fmsg_listener_t* listener, int fd)
{
    epoll_ctl(listener->epfd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
}


static int wait_event(int efd, u64* counter, int timeout)
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(efd, &readfds); // 将 eventfd 加入监听集合

    struct timeval val;
    val.tv_sec = timeout / 1000000;
    val.tv_usec = timeout % 1000000;

    int ret = select(efd + 1, &readfds, NULL, NULL, &val);
    if (ret > 0)
    {
        if (FD_ISSET(efd, &readfds))
        {
            eventfd_read(efd, (eventfd_t*)counter); // 读取计数器值并重置为0
        }
    }

    return ret;
}

/*
int fmsg_listener_wait(fmsg_listener_t* listener, int timeout, fmsg_handler_func handler)
{
#define MAX_EVENTS 4
    struct epoll_event evs[MAX_EVENTS];
    int n = epoll_wait(listener->epfd, evs, MAX_EVENTS, timeout);
    for (int i = 0; i < n; i++)
    {
        printf("recv event %d\n");
        struct epoll_event* ev = &evs[i];
        uint64_t u;
        eventfd_read(ev->data.fd, &u); //清除事件通知

        if (ev->data.fd == listener->efd)
        {
            fmsg_t* msg = NULL;
            while (rte_ring_sc_dequeue(listener->ring, (void**)&msg) == 0)
            {
                handler(msg);
                fnp_free(msg);
            }
        }
    }

    return n;
}
*/


