#include "fnp.h"

#include "fnp_error.h"
#include "fnp_internal.h"

#include <sys/epoll.h>
#include <unistd.h>

#define FNP_EPOLL_MAX_EVENTS 32

int fnp_epoll_create(void)
{
    return epoll_create1(0);
}

int fnp_epoll_add(int epfd, fnp_socket_t* socket, fnp_handler_func handler, void* arg)
{
    if (epfd < 0 || socket == NULL || socket->shared == NULL || handler == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (socket->wait_epfd >= 0)
    {
        if (socket->wait_epfd == epfd)
        {
            socket->handler = handler;
            socket->handler_arg = arg;
            fsocket_frontend_flags_set(socket->shared, FSOCKET_FRONTEND_FLAG_EVENTFD);
            return FNP_OK;
        }
        return FNP_ERR_OCCUPIED;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = socket;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, socket->shared->rx_efd_in_frontend, &ev) != 0)
    {
        return FNP_ERR_EPOLL_ADD;
    }

    socket->wait_epfd = epfd;
    socket->handler = handler;
    socket->handler_arg = arg;
    fsocket_frontend_flags_set(socket->shared, FSOCKET_FRONTEND_FLAG_EVENTFD);
    return FNP_OK;
}

int fnp_epoll_del(int epfd, fnp_socket_t* socket)
{
    if (epfd < 0 || socket == NULL || socket->shared == NULL)
    {
        return FNP_ERR_PARAM;
    }

    if (socket->wait_epfd != epfd)
    {
        return FNP_ERR_BAD_FD;
    }

    epoll_ctl(epfd, EPOLL_CTL_DEL, socket->shared->rx_efd_in_frontend, NULL);
    socket->wait_epfd = -1;
    socket->handler = NULL;
    socket->handler_arg = NULL;
    fsocket_frontend_flags_clear(socket->shared, FSOCKET_FRONTEND_FLAG_EVENTFD | FSOCKET_FRONTEND_FLAG_POLLING);
    return FNP_OK;
}

int fnp_epoll_wait(int epfd, int timeout_ms, int budget)
{
    struct epoll_event events[FNP_EPOLL_MAX_EVENTS];
    int ready = epoll_wait(epfd, events, FNP_EPOLL_MAX_EVENTS, timeout_ms);
    if (ready < 0)
    {
        return FNP_ERR_EPOLL_ADD;
    }

    int total = 0;
    for (int i = 0; i < ready; ++i)
    {
        fnp_socket_t* socket = (fnp_socket_t*)events[i].data.ptr;
        if (socket == NULL || socket->shared == NULL || socket->wait_epfd != epfd || socket->handler == NULL)
        {
            continue;
        }

        eventfd_t value = 0;
        eventfd_read(socket->shared->rx_efd_in_frontend, &value);

        int ret = frontend_drain_socket(socket, budget);
        if (ret < 0)
        {
            return ret;
        }
        total += ret;
    }

    return total;
}

void fnp_epoll_destroy(int epfd)
{
    if (epfd < 0)
    {
        return;
    }

    for (u32 i = 0; i < frontend_local.capacity; ++i)
    {
        fnp_socket_t* socket = frontend_get_fsocket(i);
        if (socket == NULL || socket->wait_epfd != epfd)
        {
            continue;
        }

        socket->wait_epfd = -1;
        socket->handler = NULL;
        socket->handler_arg = NULL;
        fsocket_frontend_flags_clear(socket->shared, FSOCKET_FRONTEND_FLAG_EVENTFD | FSOCKET_FRONTEND_FLAG_POLLING);
    }

    close(epfd);
}
