#include "fnp.h"

#include "fnp_error.h"

#include <sys/epoll.h>
#include <unistd.h>

int fnp_epoll_create(void)
{
    return epoll_create1(0);
}

int fnp_epoll_add(int epfd, fnp_socket_t *socket, fnp_handler_func handler, void *arg)
{
    (void)epfd;
    (void)socket;
    (void)handler;
    (void)arg;
    return FNP_ERR_NOT_SUPPORTED;
}

int fnp_epoll_del(int epfd, fnp_socket_t *socket)
{
    (void)epfd;
    (void)socket;
    return FNP_ERR_NOT_SUPPORTED;
}

int fnp_epoll_wait(int epfd, int timeout_ms, int budget)
{
    (void)epfd;
    (void)timeout_ms;
    (void)budget;
    return FNP_ERR_NOT_SUPPORTED;
}

void fnp_epoll_destroy(int epfd)
{
    if (epfd >= 0)
    {
        close(epfd);
    }
}
