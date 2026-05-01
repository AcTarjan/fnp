#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "fnp.h"
#include "fnp_internal.h"

#define DEMO_EXPLICIT_LOCAL_PORT 41001
#define DEMO_RECEIVER_LOCAL_PORT 41002

typedef struct ldp_demo_result
{
    char payload[128];
    int received;
} ldp_demo_result_t;

static void ldp_demo_handler(fnp_socket_t *socket, fnp_mbuf_t *m, void *arg)
{
    (void)socket;
    ldp_demo_result_t *result = arg;
    int len = fnp_get_mbuf_len(m);
    if (len >= (int)sizeof(result->payload))
    {
        len = (int)sizeof(result->payload) - 1;
    }

    memcpy(result->payload, fnp_mbuf_data(m), (size_t)len);
    result->payload[len] = '\0';
    result->received = 1;
}

static int init_demo_ifaddrs(const fnp_ifaddr_info_t **ifaddrs, u16 *ifaddr_count)
{
    int lcores[1] = {0};
    fnp_init_conf_t init_conf = {0};

    init_conf.main_lcore = 0;
    init_conf.lcores = lcores;
    init_conf.num_lcores = 1;
    init_conf.id = 101;
    snprintf(init_conf.name, sizeof(init_conf.name), "%s", "gtpu-ldp-demo");

    int ret = fnp_init(&init_conf);
    if (ret != FNP_OK)
    {
        return ret;
    }

    *ifaddrs = fnp_get_ifaddrs(ifaddr_count);
    return *ifaddrs == NULL ? FNP_ERR_NOT_FOUND : FNP_OK;
}

int main(void)
{
    int status = 1;
    const fnp_ifaddr_info_t *ifaddrs = NULL;
    u16 ifaddr_count = 0;
    int ret = init_demo_ifaddrs(&ifaddrs, &ifaddr_count);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_init failed: %d\n", ret);
        return 1;
    }

    if (ifaddr_count != 2 || ifaddrs[0].ip == 0 || ifaddrs[1].ip == 0)
    {
        fprintf(stderr, "unexpected allocated ifaddrs: count=%u\n", ifaddr_count);
        return 1;
    }

    fnp_gtpu_socket_conf_t sender_conf = {0};
    fnp_gtpu_socket_conf_t receiver_conf = {0};
    fnp_gtpu_socket_conf_t resolved_sender = {0};
    fnp_gtpu_socket_conf_t resolved_receiver = {0};
    fnp_socket_t *sender = NULL;
    fnp_socket_t *receiver = NULL;

    receiver_conf.local.family = FSOCKADDR_IPV4;
    receiver_conf.local.ip = ifaddrs[1].ip;
    receiver_conf.local.port = htons(DEMO_RECEIVER_LOCAL_PORT);
    receiver_conf.remote.family = FSOCKADDR_IPV4;
    receiver_conf.remote.ip = ifaddrs[0].ip;
    receiver_conf.remote.port = htons(DEMO_EXPLICIT_LOCAL_PORT);
    receiver_conf.incoming_teid = 0x1002;
    receiver_conf.outgoing_teid = 0x1001;

    ret = fnp_socket_create(fsocket_type_gtpu, &receiver_conf, &receiver);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create receiver failed: %d\n", ret);
        goto out;
    }

    u16 conf_len = sizeof(resolved_receiver);
    ret = fnp_socket_get_conf(receiver, &resolved_receiver, &conf_len);
    if (ret != FNP_OK || conf_len != sizeof(resolved_receiver))
    {
        fprintf(stderr, "get receiver conf failed: %d len=%u\n", ret, conf_len);
        goto out;
    }

    if (resolved_receiver.local.ip != receiver_conf.local.ip ||
        resolved_receiver.local.port != receiver_conf.local.port)
    {
        fprintf(stderr, "receiver resolved local is unexpected\n");
        goto out;
    }

    sender_conf.local.family = FSOCKADDR_IPV4;
    sender_conf.local.ip = ifaddrs[0].ip;
    sender_conf.local.port = htons(DEMO_EXPLICIT_LOCAL_PORT);
    sender_conf.remote.family = FSOCKADDR_IPV4;
    sender_conf.remote.ip = receiver_conf.local.ip;
    sender_conf.remote.port = receiver_conf.local.port;
    sender_conf.incoming_teid = 0x1001;
    sender_conf.outgoing_teid = 0x1002;

    ret = fnp_socket_create(fsocket_type_gtpu, &sender_conf, &sender);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create sender failed: %d\n", ret);
        goto out;
    }

    conf_len = sizeof(resolved_sender);
    ret = fnp_socket_get_conf(sender, &resolved_sender, &conf_len);
    if (ret != FNP_OK || conf_len != sizeof(resolved_sender))
    {
        fprintf(stderr, "get sender conf failed: %d len=%u\n", ret, conf_len);
        goto out;
    }

    if (resolved_sender.local.ip != sender_conf.local.ip ||
        resolved_sender.local.port != sender_conf.local.port)
    {
        fprintf(stderr, "sender resolved local is unexpected\n");
        goto out;
    }

    if (sender->shared->tx_efd_in_backend >= 0 || receiver->shared->tx_efd_in_backend >= 0)
    {
        fprintf(stderr, "LDP pair was not established\n");
        goto out;
    }

    ldp_demo_result_t result = {0};
    const char *payload = "gtpu-ldp-ok";
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
    {
        fprintf(stderr, "alloc mbuf failed\n");
        goto out;
    }

    memcpy(fnp_mbuf_data(m), payload, strlen(payload) + 1);
    fnp_mbuf_append_data(m, (int)strlen(payload) + 1);

    ret = fnp_socket_send(sender, m);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "send failed: %d\n", ret);
        fnp_free_mbuf(m);
        goto out;
    }

    if (sender->shared->egress_worker >= 0)
    {
        fprintf(stderr, "LDP send unexpectedly activated daemon send worker %d\n", sender->shared->egress_worker);
        goto out;
    }

    for (int i = 0; i < 1000 && !result.received; ++i)
    {
        ret = fnp_polling(receiver, ldp_demo_handler, &result);
        if (ret < 0)
        {
            break;
        }
        fnp_sleep(1000);
    }

    if (!result.received)
    {
        fprintf(stderr, "polling recv failed: %d\n", ret);
        goto out;
    }

    if (strcmp(result.payload, payload) != 0)
    {
        fprintf(stderr, "payload mismatch: %s\n", result.payload);
        goto out;
    }

    printf("GTP-U LDP demo success: %s\n", result.payload);
    status = 0;

out:
    if (receiver != NULL)
    {
        fnp_socket_close(receiver);
    }
    if (sender != NULL)
    {
        fnp_socket_close(sender);
    }
    return status;
}
