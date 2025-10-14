#include <unistd.h>

#include "fnp.h"

/* 测试内容
1. Network Path: 发给给其它服务器，192.168.11.88:8888 -> 192.168.11.99:19999
2. Local Forwarding Path: 经由FNP Daemon中转, 客户端192.168.11.88:8888 -> 192.168.11.88:19999, 服务端192.168.11.88:19999
3. Local Direct Path: 直接通信，客户端192.168.11.88:8888 -> 192.168.11.88:19999, 服务端192.168.11.88:19999 -> 192.168.11.88:8888
*/
int main(int argc, char** argv)
{
    int lcores[] = {};
    int ret = fnp_init(0, NULL, 0);
    if (ret != FNP_OK)
    {
        printf("Failed to initialize FNP: %d\n", ret);
        return ret;
    }

    fsockaddr_t local, remote;
    fsockaddr_init(&local, FSOCKADDR_IPV4, "192.168.136.88", 8888);
    fsockaddr_init(&remote, FSOCKADDR_IPV4, "192.168.136.130", 19999);
    int fd = fnp_create_socket(fnp_protocol_udp, &local, &remote, NULL);
    if (fd < 0)
    {
        printf("fail to create udp socket: %d\n", fd);
        return -1;
    }
    printf("create socket successfully: %d\n", fd);

    while (1)
    {
        fnp_mbuf_t* m = fnp_alloc_mbuf();
        if (m == NULL)
        {
            printf("fail to alloc mbuf\n");
            fnp_sleep(1000 * 1000);
            continue;
        }

        char* data = fnp_mbuf_data(m);
        sprintf(data, "hello world from fnp!");
        fnp_mbuf_append_data(m, 21);

        ret = fnp_send(fd, m);
        if (ret != FNP_OK)
        {
            printf("fail to send mbuf: %d\n", ret);
            fnp_free_mbuf(m);
            break;
        }
        printf("send successfully\n");
        fnp_sleep(1000 * 1000 * 2);
    }
}
