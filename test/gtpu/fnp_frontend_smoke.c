#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fnp.h"

#define SMOKE_MAGIC 0x464e5053U
#define DEFAULT_PAIR_COUNT 4
#define DEFAULT_MESSAGES 256
#define DEFAULT_PAYLOAD_SIZE 64
#define DEFAULT_MAIN_LCORE 7
#define DEFAULT_SERVICE_ID 201
#define DEFAULT_BASE_PORT 41000
#define DEFAULT_TIMEOUT_MS 5000
#define MAX_PAIR_COUNT 64
#define MAX_PAYLOAD_SIZE 1400

typedef struct smoke_payload_hdr
{
    uint32_t magic;
    uint16_t pair_id;
    uint16_t reserved;
    uint32_t seq;
    uint32_t payload_size;
} smoke_payload_hdr_t;

typedef struct smoke_pair
{
    fnp_socket_t *sender;
    fnp_socket_t *receiver;
    fnp_gtpu_socket_conf_t resolved_sender;
    fnp_gtpu_socket_conf_t resolved_receiver;
    uint32_t received;
    uint32_t errors;
} smoke_pair_t;

typedef struct smoke_context
{
    smoke_pair_t *pairs;
    int pair_count;
    int payload_size;
    uint32_t total_received;
    uint32_t bad_packets;
} smoke_context_t;

typedef struct smoke_options
{
    int pair_count;
    int messages;
    int payload_size;
    int main_lcore;
    int service_id;
    int base_port;
    int timeout_ms;
} smoke_options_t;

static long long monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static const char *ipv4_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr addr;
    addr.s_addr = ip;
    const char *ret = inet_ntop(AF_INET, &addr, buf, len);
    return ret == NULL ? "0.0.0.0" : ret;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --pairs N          GTP-U socket pairs, default %d\n"
            "  --messages N       messages per pair, default %d\n"
            "  --payload-size N   payload bytes, default %d\n"
            "  --main-lcore N     frontend EAL main lcore, default %d\n"
            "  --service-id N     frontend service id, default %d\n"
            "  --base-port N      explicit sender base UDP port, default %d\n"
            "  --timeout-ms N     receive timeout, default %d\n",
            prog,
            DEFAULT_PAIR_COUNT,
            DEFAULT_MESSAGES,
            DEFAULT_PAYLOAD_SIZE,
            DEFAULT_MAIN_LCORE,
            DEFAULT_SERVICE_ID,
            DEFAULT_BASE_PORT,
            DEFAULT_TIMEOUT_MS);
}

static int parse_int_arg(const char *name, const char *value, int min_value, int max_value, int *out)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < min_value || parsed > max_value)
    {
        fprintf(stderr, "invalid %s: %s, expected [%d, %d]\n", name, value, min_value, max_value);
        return FNP_ERR_PARAM;
    }

    *out = (int)parsed;
    return FNP_OK;
}

static int parse_options(int argc, char **argv, smoke_options_t *opts)
{
    static const struct option long_options[] = {
        {"pairs", required_argument, NULL, 'p'},
        {"messages", required_argument, NULL, 'm'},
        {"payload-size", required_argument, NULL, 's'},
        {"main-lcore", required_argument, NULL, 'l'},
        {"service-id", required_argument, NULL, 'i'},
        {"base-port", required_argument, NULL, 'b'},
        {"timeout-ms", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    opts->pair_count = DEFAULT_PAIR_COUNT;
    opts->messages = DEFAULT_MESSAGES;
    opts->payload_size = DEFAULT_PAYLOAD_SIZE;
    opts->main_lcore = DEFAULT_MAIN_LCORE;
    opts->service_id = DEFAULT_SERVICE_ID;
    opts->base_port = DEFAULT_BASE_PORT;
    opts->timeout_ms = DEFAULT_TIMEOUT_MS;

    int opt = 0;
    while ((opt = getopt_long(argc, argv, "p:m:s:l:i:b:t:h", long_options, NULL)) != -1)
    {
        int ret = FNP_OK;
        switch (opt)
        {
        case 'p':
            ret = parse_int_arg("--pairs", optarg, 1, MAX_PAIR_COUNT, &opts->pair_count);
            break;
        case 'm':
            ret = parse_int_arg("--messages", optarg, 1, 10000000, &opts->messages);
            break;
        case 's':
            ret = parse_int_arg("--payload-size",
                                optarg,
                                (int)sizeof(smoke_payload_hdr_t),
                                MAX_PAYLOAD_SIZE,
                                &opts->payload_size);
            break;
        case 'l':
            ret = parse_int_arg("--main-lcore", optarg, 0, 63, &opts->main_lcore);
            break;
        case 'i':
            ret = parse_int_arg("--service-id", optarg, 1, 65535, &opts->service_id);
            break;
        case 'b':
            ret = parse_int_arg("--base-port", optarg, 1024, 65000, &opts->base_port);
            break;
        case 't':
            ret = parse_int_arg("--timeout-ms", optarg, 100, 600000, &opts->timeout_ms);
            break;
        case 'h':
            usage(argv[0]);
            return 1;
        default:
            usage(argv[0]);
            return FNP_ERR_PARAM;
        }

        if (ret != FNP_OK)
        {
            return ret;
        }
    }

    if (opts->base_port + opts->pair_count >= 65535)
    {
        fprintf(stderr, "--base-port plus --pairs exceeds UDP port range\n");
        return FNP_ERR_PARAM;
    }

    return FNP_OK;
}

static int init_frontend(const smoke_options_t *opts,
                         const fnp_ifaddr_info_t **ifaddrs,
                         u16 *ifaddr_count)
{
    fnp_init_conf_t init_conf = {0};

    init_conf.main_lcore = opts->main_lcore;
    init_conf.lcores = NULL;
    init_conf.num_lcores = 0;
    init_conf.id = (u16)opts->service_id;
    snprintf(init_conf.name, sizeof(init_conf.name), "%s", "fnp-frontend-smoke");

    int ret = fnp_init(&init_conf);
    if (ret != FNP_OK)
    {
        return ret;
    }

    *ifaddrs = fnp_get_ifaddrs(ifaddr_count);
    return *ifaddrs == NULL ? FNP_ERR_NOT_FOUND : FNP_OK;
}

static void print_ifaddrs(const fnp_ifaddr_info_t *ifaddrs, u16 ifaddr_count)
{
    printf("frontend allocated ifaddrs: %u\n", ifaddr_count);
    for (u16 i = 0; i < ifaddr_count; ++i)
    {
        char ip[INET_ADDRSTRLEN];
        char gateway[INET_ADDRSTRLEN];
        printf("  ifaddr[%u] name=%s network=%s device=%s ip=%s/%u gateway=%s\n",
               i,
               ifaddrs[i].name,
               ifaddrs[i].network_name,
               ifaddrs[i].device_name,
               ipv4_to_str(ifaddrs[i].ip, ip, sizeof(ip)),
               ifaddrs[i].prefix_len,
               ipv4_to_str(ifaddrs[i].gateway, gateway, sizeof(gateway)));
    }
}

static int create_pair(int index,
                       int base_port,
                       const fnp_ifaddr_info_t *ifaddrs,
                       smoke_pair_t *pair)
{
    const uint32_t sender_teid = 0x100000U + (uint32_t)index * 2U + 1U;
    const uint32_t receiver_teid = sender_teid + 1U;

    fnp_gtpu_socket_conf_t receiver_conf = {0};
    receiver_conf.remote.family = FSOCKADDR_IPV4;
    receiver_conf.remote.ip = ifaddrs[0].ip;
    receiver_conf.remote.port = htons((uint16_t)(base_port + index));
    receiver_conf.incoming_teid = receiver_teid;
    receiver_conf.outgoing_teid = sender_teid;

    int ret = fnp_socket_create(fsocket_type_gtpu, &receiver_conf, &pair->receiver);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create receiver[%d] failed: %d\n", index, ret);
        return ret;
    }

    u16 conf_len = sizeof(pair->resolved_receiver);
    ret = fnp_socket_get_conf(pair->receiver, &pair->resolved_receiver, &conf_len);
    if (ret != FNP_OK || conf_len != sizeof(pair->resolved_receiver))
    {
        fprintf(stderr, "get receiver[%d] conf failed: ret=%d len=%u\n", index, ret, conf_len);
        return ret == FNP_OK ? FNP_ERR_GENERIC : ret;
    }

    fnp_gtpu_socket_conf_t sender_conf = {0};
    sender_conf.send_ip = ifaddrs[0].ip;
    sender_conf.send_port = htons((uint16_t)(base_port + index));
    sender_conf.remote.family = FSOCKADDR_IPV4;
    sender_conf.remote.ip = pair->resolved_receiver.send_ip;
    sender_conf.remote.port = pair->resolved_receiver.send_port;
    sender_conf.incoming_teid = sender_teid;
    sender_conf.outgoing_teid = receiver_teid;

    ret = fnp_socket_create(fsocket_type_gtpu, &sender_conf, &pair->sender);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create sender[%d] failed: %d\n", index, ret);
        return ret;
    }

    conf_len = sizeof(pair->resolved_sender);
    ret = fnp_socket_get_conf(pair->sender, &pair->resolved_sender, &conf_len);
    if (ret != FNP_OK || conf_len != sizeof(pair->resolved_sender))
    {
        fprintf(stderr, "get sender[%d] conf failed: ret=%d len=%u\n", index, ret, conf_len);
        return ret == FNP_OK ? FNP_ERR_GENERIC : ret;
    }

    char sender_ip[INET_ADDRSTRLEN];
    char receiver_ip[INET_ADDRSTRLEN];
    printf("pair[%d] %s:%u teid=%#x -> %s:%u teid=%#x\n",
           index,
           ipv4_to_str(pair->resolved_sender.send_ip, sender_ip, sizeof(sender_ip)),
           ntohs(pair->resolved_sender.send_port),
           pair->resolved_sender.outgoing_teid,
           ipv4_to_str(pair->resolved_receiver.send_ip, receiver_ip, sizeof(receiver_ip)),
           ntohs(pair->resolved_receiver.send_port),
           pair->resolved_receiver.incoming_teid);

    return FNP_OK;
}

static int fill_payload(fnp_mbuf_t *m, int payload_size, int pair_id, uint32_t seq)
{
    if (m == NULL || payload_size < (int)sizeof(smoke_payload_hdr_t))
    {
        return FNP_ERR_PARAM;
    }

    uint8_t *data = fnp_mbuf_data(m);
    memset(data, 'A' + (pair_id % 26), (size_t)payload_size);

    smoke_payload_hdr_t hdr = {
        .magic = SMOKE_MAGIC,
        .pair_id = (uint16_t)pair_id,
        .reserved = 0,
        .seq = seq,
        .payload_size = (uint32_t)payload_size,
    };
    memcpy(data, &hdr, sizeof(hdr));

    fnp_mbuf_append_data(m, payload_size);
    if (fnp_get_mbuf_len(m) != payload_size)
    {
        return FNP_ERR_MBUF_ALLOC;
    }

    return FNP_OK;
}

static void smoke_handler(fnp_socket_t *socket, fnp_mbuf_t *m, void *arg)
{
    smoke_context_t *ctx = arg;
    int pair_index = -1;
    for (int i = 0; i < ctx->pair_count; ++i)
    {
        if (ctx->pairs[i].receiver == socket)
        {
            pair_index = i;
            break;
        }
    }

    if (pair_index < 0)
    {
        ctx->bad_packets++;
        return;
    }

    smoke_pair_t *pair = &ctx->pairs[pair_index];
    int len = fnp_get_mbuf_len(m);
    if (len < (int)sizeof(smoke_payload_hdr_t))
    {
        pair->errors++;
        ctx->bad_packets++;
        ctx->total_received++;
        return;
    }

    smoke_payload_hdr_t hdr;
    memcpy(&hdr, fnp_mbuf_data(m), sizeof(hdr));
    if (hdr.magic != SMOKE_MAGIC ||
        hdr.pair_id != (uint16_t)pair_index ||
        hdr.seq != pair->received ||
        hdr.payload_size != (uint32_t)ctx->payload_size ||
        len != ctx->payload_size)
    {
        pair->errors++;
        ctx->bad_packets++;
    }

    pair->received++;
    ctx->total_received++;
}

static int add_receivers_to_epoll(int epfd, smoke_context_t *ctx)
{
    for (int i = 0; i < ctx->pair_count; ++i)
    {
        int ret = fnp_epoll_add(epfd, ctx->pairs[i].receiver, smoke_handler, ctx);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "epoll add receiver[%d] failed: %d\n", i, ret);
            return ret;
        }
    }

    return FNP_OK;
}

static int send_one(smoke_pair_t *pair, int payload_size, int pair_id, uint32_t seq)
{
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
    {
        return FNP_ERR_MBUF_ALLOC;
    }

    int ret = fill_payload(m, payload_size, pair_id, seq);
    if (ret != FNP_OK)
    {
        fnp_free_mbuf(m);
        return ret;
    }

    ret = fnp_socket_send(pair->sender, m);
    if (ret != FNP_OK)
    {
        fnp_free_mbuf(m);
        return ret;
    }

    return FNP_OK;
}

static void close_pairs(smoke_pair_t *pairs, int pair_count)
{
    if (pairs == NULL)
    {
        return;
    }

    for (int i = 0; i < pair_count; ++i)
    {
        if (pairs[i].receiver != NULL)
        {
            fnp_socket_close(pairs[i].receiver);
            pairs[i].receiver = NULL;
        }
        if (pairs[i].sender != NULL)
        {
            fnp_socket_close(pairs[i].sender);
            pairs[i].sender = NULL;
        }
    }
}

int main(int argc, char **argv)
{
    smoke_options_t opts;
    int ret = parse_options(argc, argv, &opts);
    if (ret != FNP_OK)
    {
        return ret == 1 ? 0 : 1;
    }

    const fnp_ifaddr_info_t *ifaddrs = NULL;
    u16 ifaddr_count = 0;
    ret = init_frontend(&opts, &ifaddrs, &ifaddr_count);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_init failed: %d\n", ret);
        return 1;
    }

    print_ifaddrs(ifaddrs, ifaddr_count);
    if (ifaddr_count < 2 || ifaddrs[0].ip == 0 || ifaddrs[1].ip == 0)
    {
        fprintf(stderr, "frontend smoke requires at least two allocated local ifaddrs\n");
        return 1;
    }

    smoke_context_t ctx = {
        .pair_count = opts.pair_count,
        .payload_size = opts.payload_size,
    };
    ctx.pairs = calloc((size_t)opts.pair_count, sizeof(*ctx.pairs));
    if (ctx.pairs == NULL)
    {
        fprintf(stderr, "allocate pair state failed\n");
        return 1;
    }

    int epfd = -1;
    int status = 1;
    for (int i = 0; i < opts.pair_count; ++i)
    {
        ret = create_pair(i, opts.base_port, ifaddrs, &ctx.pairs[i]);
        if (ret != FNP_OK)
        {
            goto out;
        }
    }

    epfd = fnp_epoll_create();
    if (epfd < 0)
    {
        fprintf(stderr, "create epoll failed: %d\n", epfd);
        goto out;
    }

    ret = add_receivers_to_epoll(epfd, &ctx);
    if (ret != FNP_OK)
    {
        goto out;
    }

    const uint32_t expected_total = (uint32_t)opts.pair_count * (uint32_t)opts.messages;
    long long start_ns = monotonic_ns();
    for (int seq = 0; seq < opts.messages; ++seq)
    {
        for (int i = 0; i < opts.pair_count; ++i)
        {
            ret = send_one(&ctx.pairs[i], opts.payload_size, i, (uint32_t)seq);
            if (ret != FNP_OK)
            {
                fprintf(stderr, "send pair[%d] seq=%d failed: %d\n", i, seq, ret);
                goto out;
            }
        }

        ret = fnp_epoll_wait(epfd, 0, 32);
        if (ret < 0)
        {
            fprintf(stderr, "epoll wait during send failed: %d\n", ret);
            goto out;
        }
    }

    long long deadline_ns = monotonic_ns() + (long long)opts.timeout_ms * 1000000LL;
    while (ctx.total_received < expected_total && monotonic_ns() < deadline_ns)
    {
        ret = fnp_epoll_wait(epfd, 100, 32);
        if (ret < 0)
        {
            fprintf(stderr, "epoll wait failed: %d\n", ret);
            goto out;
        }
    }
    long long end_ns = monotonic_ns();

    for (int i = 0; i < opts.pair_count; ++i)
    {
        printf("pair[%d] received=%u errors=%u\n", i, ctx.pairs[i].received, ctx.pairs[i].errors);
    }

    double seconds = (double)(end_ns - start_ns) / 1000000000.0;
    if (seconds <= 0.0)
    {
        seconds = 0.000001;
    }

    printf("FNP frontend smoke summary: pairs=%d messages_per_pair=%d payload=%dB expected=%u received=%u bad=%u throughput=%.2f msg/s %.2f Mbit/s\n",
           opts.pair_count,
           opts.messages,
           opts.payload_size,
           expected_total,
           ctx.total_received,
           ctx.bad_packets,
           (double)ctx.total_received / seconds,
           ((double)ctx.total_received * (double)opts.payload_size * 8.0) / seconds / 1000000.0);

    if (ctx.total_received == expected_total && ctx.bad_packets == 0)
    {
        printf("FNP frontend smoke PASS\n");
        status = 0;
    }
    else
    {
        fprintf(stderr, "FNP frontend smoke FAIL\n");
    }

out:
    if (epfd >= 0)
    {
        fnp_epoll_destroy(epfd);
    }
    close_pairs(ctx.pairs, opts.pair_count);
    free(ctx.pairs);
    return status;
}
