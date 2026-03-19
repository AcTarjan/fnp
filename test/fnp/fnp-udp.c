#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fnp.h"

#define UDP_DEMO_DEFAULT_FNP_IP "192.168.66.88"
#define UDP_DEMO_DEFAULT_KERNEL_IP "192.168.66.66"
#define UDP_DEMO_DEFAULT_SERVER_PORT 16666
#define UDP_DEMO_DEFAULT_CLIENT_PORT 18888
#define UDP_DEMO_MAX_PAYLOAD 2048

static void format_ipv4(u32 ip_be, char *buf, size_t buf_len)
{
    struct in_addr addr = {.s_addr = ip_be};
    if (inet_ntop(AF_INET, &addr, buf, buf_len) == NULL)
    {
        snprintf(buf, buf_len, "0.0.0.0");
    }
}

static void print_sockaddr(const char *prefix, const fsockaddr_t *addr)
{
    char ip_text[INET_ADDRSTRLEN] = {0};
    format_ipv4(addr->ip, ip_text, sizeof(ip_text));
    printf("%s%s:%u\n", prefix, ip_text, rte_be_to_cpu_16(addr->port));
}

static int build_udp_conf(fnp_udp_socket_conf_t *conf,
                          const char *local_ip, int local_port,
                          const char *remote_ip, int remote_port)
{
    memset(conf, 0, sizeof(*conf));
    int ret = fsockaddr_init(&conf->local, FSOCKADDR_IPV4, local_ip, local_port);
    if (ret != FNP_OK)
    {
        return ret;
    }

    if (remote_ip != NULL)
    {
        ret = fsockaddr_init(&conf->remote, FSOCKADDR_IPV4, remote_ip, remote_port);
        if (ret != FNP_OK)
        {
            return ret;
        }
    }

    return FNP_OK;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s server [local_ip] [local_port]\n"
            "  %s client [local_ip] [local_port] [remote_ip] [remote_port] [message] [count]\n"
            "\n"
            "Defaults:\n"
            "  server local_ip=%s local_port=%d\n"
            "  client local_ip=%s local_port=%d remote_ip=%s remote_port=%d\n"
            "\n"
            "Examples:\n"
            "  %s server\n"
            "  %s client\n",
            prog, prog,
            UDP_DEMO_DEFAULT_FNP_IP, UDP_DEMO_DEFAULT_SERVER_PORT,
            UDP_DEMO_DEFAULT_FNP_IP, UDP_DEMO_DEFAULT_CLIENT_PORT,
            UDP_DEMO_DEFAULT_KERNEL_IP, UDP_DEMO_DEFAULT_SERVER_PORT,
            prog, prog);
}

static int udp_server_handler(fnp_socket_t *socket, fnp_mbuf_t *m, void *arg)
{
    (void)arg;

    fnp_mbuf_info_t *info = fnp_get_mbuf_info(m);
    int len = fnp_get_mbuf_len(m);
    const u8 *data = fnp_mbuf_data(m);

    char peer_ip[INET_ADDRSTRLEN] = {0};
    format_ipv4(info->remote.ip, peer_ip, sizeof(peer_ip));
    printf("server recv %d bytes from %s:%u: %.*s\n",
           len,
           peer_ip,
           rte_be_to_cpu_16(info->remote.port),
           len,
           (const char *)data);

    fnp_mbuf_t *reply = fnp_alloc_mbuf();
    if (reply == NULL)
    {
        fprintf(stderr, "fail to alloc reply mbuf\n");
        return FNP_ERR_MBUF_ALLOC;
    }

    memcpy(fnp_mbuf_data(reply), data, (size_t)len);
    fnp_mbuf_append_data(reply, len);

    int ret = fnp_socket_sendto(socket, reply, &info->remote);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to send echo reply: %d\n", ret);
        fnp_free_mbuf(reply);
        return ret;
    }

    return FNP_OK;
}

static int run_server(const char *local_ip, int local_port)
{
    fnp_udp_socket_conf_t conf;
    int ret = build_udp_conf(&conf, local_ip, local_port, NULL, 0);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to build server socket conf: %d\n", ret);
        return ret;
    }

    fnp_socket_t *socket = NULL;
    ret = fnp_socket_create(fsocket_type_udp, &conf, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to create udp server socket: %d\n", ret);
        return ret;
    }

    print_sockaddr("udp server listen on ", &conf.local);

    int epfd = fnp_epoll_create();
    if (epfd < 0)
    {
        fprintf(stderr, "fail to create epoll fd: %d\n", epfd);
        fnp_socket_close(socket);
        return epfd;
    }

    ret = fnp_epoll_add(epfd, socket, udp_server_handler, NULL);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to add udp server socket to epoll: %d\n", ret);
        fnp_epoll_destroy(epfd);
        fnp_socket_close(socket);
        return ret;
    }

    while (1)
    {
        ret = fnp_epoll_wait(epfd, -1, 64);
        if (ret < 0)
        {
            fprintf(stderr, "fnp_epoll_wait failed: %d\n", ret);
            break;
        }
    }

    fnp_epoll_destroy(epfd);
    fnp_socket_close(socket);
    return ret;
}

static int run_client(const char *local_ip, int local_port,
                      const char *remote_ip, int remote_port,
                      const char *message, int count)
{
    fnp_udp_socket_conf_t conf;
    int ret = build_udp_conf(&conf, local_ip, local_port, remote_ip, remote_port);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to build client socket conf: %d\n", ret);
        return ret;
    }

    fnp_socket_t *socket = NULL;
    ret = fnp_socket_create(fsocket_type_udp, &conf, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to create udp client socket: %d\n", ret);
        return ret;
    }

    print_sockaddr("udp client local  ", &conf.local);
    print_sockaddr("udp client remote ", &conf.remote);

    char payload[UDP_DEMO_MAX_PAYLOAD] = {0};
    char reply[UDP_DEMO_MAX_PAYLOAD + 1] = {0};

    for (int i = 0; i < count; ++i)
    {
        printf("client preparing request %d/%d\n", i + 1, count);
        int payload_len = snprintf(payload, sizeof(payload), "%s%s%d",
                                   message,
                                   count > 1 ? " #" : "",
                                   count > 1 ? i + 1 : 0);
        if (payload_len < 0 || payload_len >= (int)sizeof(payload))
        {
            fprintf(stderr, "payload is too long\n");
            fnp_socket_close(socket);
            return FNP_ERR_PARAM;
        }

        printf("client allocating mbuf\n");
        fnp_mbuf_t *m = fnp_alloc_mbuf();
        if (m == NULL)
        {
            fprintf(stderr, "fail to alloc client mbuf\n");
            fnp_socket_close(socket);
            return FNP_ERR_MBUF_ALLOC;
        }

        memcpy(fnp_mbuf_data(m), payload, (size_t)payload_len);
        fnp_mbuf_append_data(m, payload_len);

        printf("client sending request\n");
        ret = fnp_socket_send(socket, m);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "fail to send request: %d\n", ret);
            fnp_free_mbuf(m);
            fnp_socket_close(socket);
            return ret;
        }

        printf("client send %d bytes: %s\n", payload_len, payload);

        fsockaddr_t peer = {0};
        printf("client waiting for reply\n");
        ret = fnp_socket_recvfrom(socket, (u8 *)reply, UDP_DEMO_MAX_PAYLOAD, &peer);
        if (ret < 0)
        {
            fprintf(stderr, "fail to recv reply: %d\n", ret);
            fnp_socket_close(socket);
            return ret;
        }

        reply[ret] = '\0';

        char peer_ip[INET_ADDRSTRLEN] = {0};
        format_ipv4(peer.ip, peer_ip, sizeof(peer_ip));
        printf("client recv %d bytes from %s:%u: %s\n",
               ret,
               peer_ip,
               rte_be_to_cpu_16(peer.port),
               reply);
    }

    fnp_socket_close(socket);
    return FNP_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    int ret = fnp_init(0, NULL, 0);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to initialize fnp frontend: %d\n", ret);
        return ret;
    }

    if (strcmp(argv[1], "server") == 0)
    {
        const char *local_ip = argc > 2 ? argv[2] : UDP_DEMO_DEFAULT_FNP_IP;
        int local_port = argc > 3 ? atoi(argv[3]) : UDP_DEMO_DEFAULT_SERVER_PORT;
        return run_server(local_ip, local_port);
    }

    if (strcmp(argv[1], "client") == 0)
    {
        const char *local_ip = argc > 2 ? argv[2] : UDP_DEMO_DEFAULT_FNP_IP;
        int local_port = argc > 3 ? atoi(argv[3]) : UDP_DEMO_DEFAULT_CLIENT_PORT;
        const char *remote_ip = argc > 4 ? argv[4] : UDP_DEMO_DEFAULT_KERNEL_IP;
        int remote_port = argc > 5 ? atoi(argv[5]) : UDP_DEMO_DEFAULT_SERVER_PORT;
        const char *message = argc > 6 ? argv[6] : "hello from fnp udp demo";
        int count = argc > 7 ? atoi(argv[7]) : 1;
        if (count <= 0)
        {
            count = 1;
        }
        return run_client(local_ip, local_port, remote_ip, remote_port, message, count);
    }

    usage(argv[0]);
    return 1;
}
