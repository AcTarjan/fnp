#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "fnp.h"


int handle_incoming_packet(int fd)
{
    fnp_mbuf_t* m = NULL;
    int ret = fnp_recv(fd, &m);
    if (ret != FNP_OK)
    {
        printf("recv mbuf failed: %d\n", ret);
        return ret;
    }

    void* data = fnp_mbuf_data(m);
    int len = fnp_get_mbuf_len(m);
    printf("recv %d bytes: %s\n", len, (char*)data);
    fnp_free_mbuf(m);
    return FNP_OK;
}

int handle_incoming_packet_with_loop(void* arg)
{
    int fd = *(int*)arg;
    printf("handle_incoming_packet_with_loop from %d on %d\n", fd, rte_lcore_id());
    while (1)
    {
        handle_incoming_packet(fd);
    }
}

int handle_incoming_packet_with_epoll(void* arg)
{
    int fd = *(int*)arg;
    printf("handle_incoming_packet_with_epoll from %d on %d\n", fd, rte_lcore_id());

    // 创建epoll
    int epoll_fd = epoll_create1(0);

    // 添加fd到epoll实例
    struct epoll_event ev = {0}; // 注意必须初始化为0，否则异常
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    while (1)
    {
#define MAX_EVENTS  4
        static struct epoll_event evs[MAX_EVENTS];
        int n = epoll_wait(epoll_fd, evs, MAX_EVENTS, -1);
        for (int i = 0; i < n; i++)
        {
            eventfd_t value;
            struct epoll_event* ev = &evs[i];
            eventfd_read(ev->data.fd, &value);
            handle_incoming_packet(ev->data.fd);
        }
    }
}

int main(int argc, char** argv)
{
    int lcores[] = {7};
    int ret = fnp_init(0, lcores, 1);
    if (ret != FNP_OK)
    {
        printf("Failed to initialize FNP: %d\n", ret);
        return ret;
    }

    fsockaddr_t local, remote;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 19999);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, 0, 0);
    int fd = fnp_create_socket(fnp_protocol_udp, &local, NULL, NULL);
    if (fd < 0)
    {
        printf("fail to create udp socket: %d\n", fd);
        return -1;
    }
    printf("create socket successfully: %d\n", fd);

    ret = fnp_launch_on_lcore(handle_incoming_packet_with_epoll, &fd, -1);
    if (ret != FNP_OK)
    {
        printf("Failed to launch handle_incoming_packet: %d\n", ret);
        return ret;
    }


    while (1)
    {
        fnp_sleep(1000 * 1000 * 100);
    }
}
