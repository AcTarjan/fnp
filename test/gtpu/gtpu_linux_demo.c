#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fnp.h"

#define DEMO_EXPLICIT_LOCAL_PORT 41011

typedef struct gtpu_demo_result
{
    char payload[256];
    int received;
} gtpu_demo_result_t;

static void gtpu_demo_handler(fnp_socket_t *socket, fnp_mbuf_t *m, void *arg)
{
    (void)socket;
    gtpu_demo_result_t *result = arg;
    int len = fnp_get_mbuf_len(m);
    if (len >= (int)sizeof(result->payload))
    {
        len = (int)sizeof(result->payload) - 1;
    }

    memcpy(result->payload, fnp_mbuf_data(m), (size_t)len);
    result->payload[len] = '\0';
    result->received = 1;
}

static int parse_ipv4_text(const char *text, u32 *ip_be)
{
    struct in_addr addr = {0};
    if (text == NULL || ip_be == NULL || inet_pton(AF_INET, text, &addr) != 1)
    {
        return FNP_ERR_PARAM;
    }

    *ip_be = addr.s_addr;
    return FNP_OK;
}

static int init_demo_ifaddrs(const fnp_ifaddr_info_t **ifaddrs, u16 *ifaddr_count)
{
    int lcores[1] = {0};
    fnp_init_conf_t init_conf = {0};

    init_conf.main_lcore = 0;
    init_conf.lcores = lcores;
    init_conf.num_lcores = 1;
    init_conf.id = 102;
    snprintf(init_conf.name, sizeof(init_conf.name), "%s", "gtpu-linux-demo");

    int ret = fnp_init(&init_conf);
    if (ret != FNP_OK)
    {
        return ret;
    }

    *ifaddrs = fnp_get_ifaddrs(ifaddr_count);
    return *ifaddrs == NULL ? FNP_ERR_NOT_FOUND : FNP_OK;
}

static const fnp_ifaddr_info_t *find_ifaddr_by_ip(const fnp_ifaddr_info_t *ifaddrs, u16 ifaddr_count, u32 ip_be)
{
    for (u16 i = 0; i < ifaddr_count; ++i)
    {
        if (ifaddrs[i].ip == ip_be)
        {
            return &ifaddrs[i];
        }
    }

    return NULL;
}

int main(int argc, char **argv)
{
    const char *remote_ip = argc > 1 ? argv[1] : "192.168.66.66";
    const char *payload = argc > 2 ? argv[2] : "gtpu-linux-ok";
    const char *local_mode = argc > 3 ? argv[3] : "explicit";
    u16 requested_local_port = (u16)(argc > 4 ? atoi(argv[4]) : (strcmp(local_mode, "auto") == 0 ? 0 : DEMO_EXPLICIT_LOCAL_PORT));
    u16 requested_remote_port = (u16)(argc > 5 ? atoi(argv[5]) : 0);
    const char *requested_local_ip_text = argc > 6 ? argv[6] : NULL;
    int status = 1;
    const fnp_ifaddr_info_t *ifaddrs = NULL;
    u16 ifaddr_count = 0;
    int ret = init_demo_ifaddrs(&ifaddrs, &ifaddr_count);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_init failed: %d\n", ret);
        return 1;
    }

    if (ifaddr_count == 0 || ifaddrs[0].ip == 0)
    {
        fprintf(stderr, "invalid static ifaddrs\n");
        return 1;
    }

    const fnp_ifaddr_info_t *selected_ifaddr = &ifaddrs[0];
    if (strcmp(local_mode, "auto") != 0 && requested_local_ip_text != NULL && requested_local_ip_text[0] != '\0')
    {
        u32 requested_local_ip = 0;
        ret = parse_ipv4_text(requested_local_ip_text, &requested_local_ip);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "invalid explicit local ip: %s\n", requested_local_ip_text);
            return 1;
        }

        selected_ifaddr = find_ifaddr_by_ip(ifaddrs, ifaddr_count, requested_local_ip);
        if (selected_ifaddr == NULL)
        {
            fprintf(stderr, "explicit local ip is not owned by FNP: %s\n", requested_local_ip_text);
            return 1;
        }
    }

    fnp_gtpu_socket_conf_t conf = {0};
    fnp_gtpu_socket_conf_t resolved_conf = {0};
    conf.send_ip = strcmp(local_mode, "auto") == 0 ? 0 : selected_ifaddr->ip;
    conf.send_port = requested_local_port == 0 ? 0 : htons(requested_local_port);
    fsockaddr_init(&conf.remote, FSOCKADDR_IPV4, remote_ip, requested_remote_port);
    conf.incoming_teid = 0x2002;
    conf.outgoing_teid = 0x2001;

    fnp_socket_t *socket = NULL;
    int epfd = -1;
    ret = fnp_socket_create(fsocket_type_gtpu, &conf, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create gtpu socket failed: %d\n", ret);
        goto out;
    }

    u16 conf_len = sizeof(resolved_conf);
    ret = fnp_socket_get_conf(socket, &resolved_conf, &conf_len);
    if (ret != FNP_OK || conf_len != sizeof(resolved_conf))
    {
        fprintf(stderr, "get gtpu socket conf failed: %d len=%u\n", ret, conf_len);
        goto out;
    }

    if (resolved_conf.send_ip != selected_ifaddr->ip)
    {
        fprintf(stderr, "resolved local ip mismatch\n");
        goto out;
    }

    if (requested_local_port == 0)
    {
        if (resolved_conf.send_port == 0 || ntohs(resolved_conf.send_port) == FNP_GTPU_UDP_PORT)
        {
            fprintf(stderr, "auto local port is unexpected\n");
            goto out;
        }
    }
    else if (resolved_conf.send_port != htons(requested_local_port))
    {
        fprintf(stderr, "explicit local port mismatch\n");
        goto out;
    }

    epfd = fnp_epoll_create();
    if (epfd < 0)
    {
        fprintf(stderr, "create epoll failed: %d\n", epfd);
        goto out;
    }

    gtpu_demo_result_t result = {0};
    ret = fnp_epoll_add(epfd, socket, gtpu_demo_handler, &result);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "epoll add failed: %d\n", ret);
        goto out;
    }

    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
    {
        fprintf(stderr, "alloc mbuf failed\n");
        goto out;
    }

    memcpy(fnp_mbuf_data(m), payload, strlen(payload) + 1);
    fnp_mbuf_append_data(m, (int)strlen(payload) + 1);

    ret = fnp_socket_send(socket, m);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "send failed: %d\n", ret);
        fnp_free_mbuf(m);
        goto out;
    }

    ret = fnp_epoll_wait(epfd, 1000, 8);
    if (ret <= 0 || !result.received)
    {
        fprintf(stderr, "epoll recv failed: %d\n", ret);
        goto out;
    }

    if (strcmp(result.payload, payload) != 0)
    {
        fprintf(stderr, "payload mismatch: %s\n", result.payload);
        goto out;
    }

    printf("GTP-U normal path demo success: %s\n", result.payload);
    status = 0;

out:
    if (epfd >= 0)
    {
        fnp_epoll_destroy(epfd);
    }
    if (socket != NULL)
    {
        fnp_socket_close(socket);
    }
    return status;
}