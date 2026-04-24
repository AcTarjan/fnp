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

int fnp_epoll_add(int epfd, fnp_socket_t *socket, fnp_handler_func handler, void *arg)
{
    if (unlikely(epfd < 0 || socket == NULL || socket->shared == NULL || handler == NULL))
    {
        return FNP_ERR_PARAM;
    }

    fsocket_t *shared_socket = socket->shared;

    if (socket->wait_epfd >= 0)
    {
        if (socket->wait_epfd == epfd)
        {
            socket->handler = handler;
            socket->handler_arg = arg;
            fsocket_frontend_flags_set(shared_socket, FSOCKET_FRONTEND_FLAG_EVENTFD);
            return FNP_OK;
        }
        return FNP_ERR_OCCUPIED;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = socket;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, shared_socket->rx_efd_in_frontend, &ev) != 0)
    {
        return FNP_ERR_EPOLL_ADD;
    }

    socket->wait_epfd = epfd;
    socket->handler = handler;
    socket->handler_arg = arg;
    fsocket_frontend_flags_set(shared_socket, FSOCKET_FRONTEND_FLAG_EVENTFD);
    return FNP_OK;
}

int fnp_epoll_del(int epfd, fnp_socket_t *socket)
{
    if (unlikely(epfd < 0 || socket == NULL || socket->shared == NULL))
    {
        return FNP_ERR_PARAM;
    }

    fsocket_t *shared_socket = socket->shared;

    if (socket->wait_epfd != epfd)
    {
        return FNP_ERR_BAD_FD;
    }

    epoll_ctl(epfd, EPOLL_CTL_DEL, shared_socket->rx_efd_in_frontend, NULL);
    socket->wait_epfd = -1;
    socket->handler = NULL;
    socket->handler_arg = NULL;
    fsocket_frontend_flags_clear(shared_socket, FSOCKET_FRONTEND_FLAG_EVENTFD | FSOCKET_FRONTEND_FLAG_POLLING);
    return FNP_OK;
}

int fnp_epoll_wait(int epfd, int timeout_ms, int budget)
{
    if (unlikely(epfd < 0))
    {
        return FNP_ERR_PARAM;
    }

    struct epoll_event events[FNP_EPOLL_MAX_EVENTS];
    int ready = epoll_wait(epfd, events, FNP_EPOLL_MAX_EVENTS, timeout_ms);
    if (unlikely(ready < 0))
    {
        return FNP_ERR_EPOLL_WAIT;
    }

    int total = 0;
    int dequeue_budget = budget;
    if (dequeue_budget <= 0 || dequeue_budget > RECV_BATCH_SIZE)
    {
        dequeue_budget = RECV_BATCH_SIZE;
    }

    for (int i = 0; i < ready; ++i)
    {
        fnp_socket_t *socket = (fnp_socket_t *)events[i].data.ptr;
        if (unlikely(socket == NULL || socket->handler == NULL || socket->wait_epfd != epfd))
        {
            continue;
        }

        fsocket_t *shared_socket = socket->shared;
        if (unlikely(shared_socket == NULL))
        {
            continue;
        }

        eventfd_t value = 0;
        while (eventfd_read(shared_socket->rx_efd_in_frontend, &value) == 0)
        {
        }

        struct rte_mbuf *mbufs[RECV_BATCH_SIZE] = {0};
        fsocket_frontend_flags_set(shared_socket, FSOCKET_FRONTEND_FLAG_POLLING);
        u32 burst = fnp_ring_dequeue_burst(shared_socket->rx, (void **)mbufs, (u32)dequeue_budget);
        if (unlikely(burst == 0))
        {
            fsocket_frontend_flags_clear(shared_socket, FSOCKET_FRONTEND_FLAG_POLLING);
            if (fnp_ring_count(shared_socket->rx) > 0 && fsocket_frontend_eventfd_enabled(shared_socket))
            {
                eventfd_write(shared_socket->rx_efd_in_frontend, 1);
            }
            continue;
        }

        for (u32 j = 0; j < burst; ++j)
        {
            socket->handler(socket, mbufs[j], socket->handler_arg);
            fnp_free_mbuf(mbufs[j]);
        }

        fsocket_frontend_flags_clear(shared_socket, FSOCKET_FRONTEND_FLAG_POLLING);
        if (fnp_ring_count(shared_socket->rx) > 0 && fsocket_frontend_eventfd_enabled(shared_socket))
        {
            eventfd_write(shared_socket->rx_efd_in_frontend, 1);
        }

        total += (int)burst;
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
        fnp_socket_t *socket = frontend_get_fsocket(i);
        if (socket == NULL || socket->wait_epfd != epfd)
        {
            continue;
        }

        fsocket_t *shared_socket = socket->shared;
        if (shared_socket == NULL)
        {
            socket->wait_epfd = -1;
            socket->handler = NULL;
            socket->handler_arg = NULL;
            continue;
        }

        socket->wait_epfd = -1;
        socket->handler = NULL;
        socket->handler_arg = NULL;
        fsocket_frontend_flags_clear(shared_socket, FSOCKET_FRONTEND_FLAG_EVENTFD | FSOCKET_FRONTEND_FLAG_POLLING);
    }

    close(epfd);
}
