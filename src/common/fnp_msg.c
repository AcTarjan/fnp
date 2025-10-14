#include "fnp_msg.h"

#include <unistd.h>

#include "hash.h"
#include "fnp_error.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>

#include "fnp_ring.h"

#define MAX_LISTENERS 8
//
// // 数组长度为10
// static fmsg_listener_t** listeners = NULL;
// // id 对于worker_id
//
// #define FMSG_CENTER_TABLE_NAME "fmsg_center"
//
// int init_fmsg_center()
// {
//     if (rte_eal_process_type() == RTE_PROC_PRIMARY)
//     {
//         const struct rte_memzone* mz = rte_memzone_reserve(
//             FMSG_CENTER_TABLE_NAME, // 唯一标识符，其他进程通过此名称查找
//             sizeof(fmsg_listener_t*) * MAX_LISTENERS, // 数组大小
//             SOCKET_ID_ANY, // NUMA节点（任意）
//             RTE_MEMZONE_IOVA_CONTIG // 确保物理地址连续（可选）
//         );
//         if (mz == NULL)
//             rte_exit(EXIT_FAILURE, "Failed to reserve memzone\n");
//         listeners = mz->addr;
//     }
//     else
//     {
//         const struct rte_memzone* mz = rte_memzone_lookup(FMSG_CENTER_TABLE_NAME);
//         if (mz == NULL)
//             rte_exit(EXIT_FAILURE, "Shared array not found\n");
//         listeners = mz->addr;
//     }
//
//     return FNP_OK;
// }

fnp_msg_t* fmsg_new(fmsg_type_t type)
{
    fnp_msg_t* msg = fnp_malloc(sizeof(fnp_msg_t));
    if (msg == NULL)
    {
        return NULL;
    }

    msg->type = type;
    msg->is_reply = false;
    return msg;
}

bool fchannel_enqueue(fchannel_t* chan, void* data)
{
    if (fnp_ring_enqueue(chan->ring, data) == 0)
    {
        return;
    }

    eventfd_write(chan->event_fd, 1); // 通知工作线程有数据到来
}


void fchannel_free(fchannel_t* chan)
{
    close(chan->event_fd);
    fnp_ring_free(chan->ring);
    fnp_free(chan);
}

void fchannel_init(fchannel_t* chan, int efd, fnp_ring_t* ring)
{
    chan->event_fd = efd;
    chan->ring = ring;
}

fchannel_t* fchannel_create(i32 size)
{
    fchannel_t* chan = fnp_malloc(sizeof(fchannel_t));
    if (chan == NULL)
    {
        return NULL;
    }

    chan->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (chan->event_fd < 0)
    {
        fnp_free(chan);
        return NULL;
    }

    chan->ring = fnp_ring_create(size, true, false);
    if (chan->ring == NULL)
    {
        close(chan->event_fd);
        fnp_free(chan);
        return NULL;
    }

    return chan;
}

void fchannel_handle(fchannel_t* chan, fmsg_handler_func handler)
{
    eventfd_t value;
    eventfd_read(chan->event_fd, &value); //清除事件fd计数

    fnp_msg_t* msg = NULL;
    while (fnp_ring_dequeue(chan->ring, (void**)&msg) != 0)
    {
        handler(msg);
        // fnp_free(msg);
    }
}

int fmsg_send(fchannel_t* chan, fnp_msg_t* msg)
{
    if (fnp_ring_enqueue(chan->ring, msg) == 0)
    {
        return FNP_ERR_RING_FULL;
    }

    eventfd_write(chan->event_fd, 1); // 通知事件发生
    return FNP_OK;
}

int fmsg_send_with_reply(fchannel_t* chan, fnp_msg_t* msg)
{
    fmsg_send(chan, msg);

    //TODO: 设置超时
    while (!msg->is_reply);
    if (msg->code < 0)
    {
        fnp_free(msg);
        return msg->code;
    }

    return FNP_OK;
}


void fmsg_send_reply(fnp_msg_t* msg)
{
    msg->is_reply = true;
}

int fnp_create_timerfd(int timeout, bool periodic)
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
