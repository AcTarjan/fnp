#define _GNU_SOURCE

#include "fnp.h"
#include "fnp_error.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PPS 1000000ULL
#define DEFAULT_KPPS 1000.0
#define DEFAULT_PAYLOAD_BYTES 256U
#define DEFAULT_DURATION_S 60U
#define DEFAULT_DRAIN_S 0U
#define DEFAULT_LOCAL_PORT 2152U
#define DEFAULT_INCOMING_TEID 0x1001U
#define DEFAULT_OUTGOING_TEID 0x1001U
#define DEFAULT_RX_LOCAL_IP "192.168.100.3"
#define DEFAULT_RX_REMOTE_IP "192.168.100.5"
#define DEFAULT_TX_LOCAL_IP "192.168.100.5"
#define DEFAULT_TX_REMOTE_IP "192.168.100.3"
#define DEFAULT_LDP_RX_LOCAL_IP "192.168.100.3"
#define DEFAULT_LDP_RX_REMOTE_IP "192.168.100.2"
#define DEFAULT_LDP_TX_LOCAL_IP "192.168.100.2"
#define DEFAULT_LDP_TX_REMOTE_IP "192.168.100.3"
#define DEFAULT_RTT_OUTPUT "/results/rtt.csv"
#define PRINT_CHECK_MASK 4095U
#define RTT_CSV_BUFFER_SIZE (16U * 1024U * 1024U)

typedef struct __attribute__((packed)) ping_payload_hdr
{
    uint64_t seq;
    uint64_t tx_ns;
} ping_payload_hdr_t;

typedef struct demo_args
{
    const char *mode;
    const char *test;
    const char *path;
    const char *local_ip;
    const char *remote_ip;
    const char *output;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t incoming_teid;
    uint32_t outgoing_teid;
    uint64_t pps;
    uint32_t payload_bytes;
    uint32_t duration_s;
    uint32_t drain_s;
    uint32_t rx_window_s;
    int service_id;
    int main_lcore;
    int bind_core;
} demo_args_t;

typedef struct demo_lcore_job
{
    const demo_args_t *args;
    atomic_bool done;
    int ret;
} demo_lcore_job_t;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double to_kpps(double pps)
{
    return pps / 1000.0;
}

static int parse_u64(const char *value, uint64_t *out)
{
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (end == value || *end != '\0')
        return -1;
    *out = (uint64_t)parsed;
    return 0;
}

static int parse_double(const char *value, double *out)
{
    char *end = NULL;
    double parsed = strtod(value, &end);
    if (end == value || *end != '\0' || parsed < 0.0)
        return -1;
    *out = parsed;
    return 0;
}

static int parse_u32(const char *value, uint32_t *out)
{
    uint64_t parsed = 0;
    if (parse_u64(value, &parsed) != 0 || parsed > UINT32_MAX)
        return -1;
    *out = (uint32_t)parsed;
    return 0;
}

static int parse_int(const char *value, int *out)
{
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0')
        return -1;
    *out = (int)parsed;
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --mode rx|tx --test pps|rtt --payload-bytes N --kpps N [options]\n"
            "Options:\n"
            "  --test pps|rtt          pps for throughput, rtt for timestamp echo test, default pps\n"
            "  --kpps N                 offered rate in kpps for TX and RX drop baseline, default %.3f\n"
            "  --pps N                  offered packet rate for TX and RX drop baseline\n"
            "  --payload-bytes N        payload size, default %u\n"
            "  --duration-s N           measured send/receive window, default %u\n"
            "  --path cross|ldp         default from FNP_NODE_PERF_PATH or cross\n"
            "  --drain-s N              deprecated, ignored\n"
            "  --rx-window-s N          total RX wall-clock window; default duration\n"
            "  --output FILE            RTT CSV output, default %s\n"
            "  --local-ip IP            default rx=%s tx=%s\n"
            "  --remote-ip IP           default rx=%s tx=%s\n"
            "  --local-port N           local GTP-U UDP port, default %u\n"
            "  --remote-port N          remote GTP-U UDP port, default %u\n"
            "  --incoming-teid N        incoming TEID, default %#x\n"
            "  --outgoing-teid N        outgoing TEID, default %#x\n"
            "  --service-id N           FNP frontend service id\n"
            "  --main-lcore N           DPDK secondary main lcore\n"
            "  --bind-core N            application lcore launched by fnp_lcore_launch\n",
            prog,
            DEFAULT_KPPS,
            DEFAULT_PAYLOAD_BYTES,
            DEFAULT_DURATION_S,
            DEFAULT_RTT_OUTPUT,
            DEFAULT_RX_LOCAL_IP,
            DEFAULT_TX_LOCAL_IP,
            DEFAULT_RX_REMOTE_IP,
            DEFAULT_TX_REMOTE_IP,
            DEFAULT_LOCAL_PORT,
            DEFAULT_LOCAL_PORT,
            DEFAULT_INCOMING_TEID,
            DEFAULT_OUTGOING_TEID);
}

static int parse_args(int argc, char **argv, demo_args_t *args)
{
    *args = (demo_args_t){
        .mode = NULL,
        .test = "pps",
        .path = NULL,
        .local_ip = NULL,
        .remote_ip = NULL,
        .output = DEFAULT_RTT_OUTPUT,
        .local_port = DEFAULT_LOCAL_PORT,
        .remote_port = DEFAULT_LOCAL_PORT,
        .incoming_teid = DEFAULT_INCOMING_TEID,
        .outgoing_teid = DEFAULT_OUTGOING_TEID,
        .pps = DEFAULT_PPS,
        .payload_bytes = DEFAULT_PAYLOAD_BYTES,
        .duration_s = DEFAULT_DURATION_S,
        .drain_s = DEFAULT_DRAIN_S,
        .rx_window_s = 0,
        .service_id = -1,
        .main_lcore = -1,
        .bind_core = -1,
    };

    for (int i = 1; i < argc; ++i)
    {
        const char *opt = argv[i];
        const char *val = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(opt, "--help") == 0)
        {
            usage(argv[0]);
            exit(0);
        }
        else if (val == NULL)
        {
            usage(argv[0]);
            return -1;
        }
        else if (strcmp(opt, "--mode") == 0)
        {
            args->mode = val;
            ++i;
        }
        else if (strcmp(opt, "--test") == 0)
        {
            args->test = val;
            ++i;
        }
        else if (strcmp(opt, "--path") == 0)
        {
            args->path = val;
            ++i;
        }
        else if (strcmp(opt, "--local-ip") == 0)
        {
            args->local_ip = val;
            ++i;
        }
        else if (strcmp(opt, "--remote-ip") == 0)
        {
            args->remote_ip = val;
            ++i;
        }
        else if (strcmp(opt, "--output") == 0)
        {
            args->output = val;
            ++i;
        }
        else if (strcmp(opt, "--pps") == 0)
        {
            if (parse_u64(val, &args->pps) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--kpps") == 0)
        {
            double kpps = 0.0;
            if (parse_double(val, &kpps) != 0)
                return -1;
            args->pps = (uint64_t)(kpps * 1000.0 + 0.5);
            ++i;
        }
        else if (strcmp(opt, "--payload-bytes") == 0)
        {
            if (parse_u32(val, &args->payload_bytes) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--duration-s") == 0)
        {
            if (parse_u32(val, &args->duration_s) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--drain-s") == 0)
        {
            if (parse_u32(val, &args->drain_s) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--rx-window-s") == 0)
        {
            if (parse_u32(val, &args->rx_window_s) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--local-port") == 0)
        {
            uint32_t port = 0;
            if (parse_u32(val, &port) != 0 || port > UINT16_MAX)
                return -1;
            args->local_port = (uint16_t)port;
            ++i;
        }
        else if (strcmp(opt, "--remote-port") == 0)
        {
            uint32_t port = 0;
            if (parse_u32(val, &port) != 0 || port > UINT16_MAX)
                return -1;
            args->remote_port = (uint16_t)port;
            ++i;
        }
        else if (strcmp(opt, "--incoming-teid") == 0)
        {
            if (parse_u32(val, &args->incoming_teid) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--outgoing-teid") == 0)
        {
            if (parse_u32(val, &args->outgoing_teid) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--service-id") == 0)
        {
            if (parse_int(val, &args->service_id) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--main-lcore") == 0)
        {
            if (parse_int(val, &args->main_lcore) != 0)
                return -1;
            ++i;
        }
        else if (strcmp(opt, "--bind-core") == 0)
        {
            if (parse_int(val, &args->bind_core) != 0)
                return -1;
            ++i;
        }
        else
        {
            usage(argv[0]);
            return -1;
        }
    }

    if (args->mode == NULL ||
        (strcmp(args->mode, "rx") != 0 && strcmp(args->mode, "tx") != 0 &&
         strcmp(args->mode, "ping") != 0 && strcmp(args->mode, "pong") != 0) ||
        (strcmp(args->test, "pps") != 0 && strcmp(args->test, "rtt") != 0) ||
        args->pps == 0 || args->payload_bytes == 0 ||
        args->incoming_teid == 0 || args->outgoing_teid == 0)
    {
        usage(argv[0]);
        return -1;
    }

    if (args->path == NULL)
        args->path = getenv("FNP_NODE_PERF_PATH");
    if (args->path == NULL || args->path[0] == '\0')
        args->path = "cross";
    if (strcmp(args->path, "cross") != 0 && strcmp(args->path, "ldp") != 0)
    {
        fprintf(stderr, "invalid path: %s\n", args->path);
        return -1;
    }

    if (strcmp(args->mode, "ping") == 0)
    {
        args->mode = "tx";
        args->test = "rtt";
    }
    else if (strcmp(args->mode, "pong") == 0)
    {
        args->mode = "rx";
        args->test = "rtt";
    }

    const bool is_tx = strcmp(args->mode, "tx") == 0;
    const bool is_ldp = strcmp(args->path, "ldp") == 0;
    if (args->local_ip == NULL)
        args->local_ip = is_ldp
                             ? (is_tx ? DEFAULT_LDP_TX_LOCAL_IP : DEFAULT_LDP_RX_LOCAL_IP)
                             : (is_tx ? DEFAULT_TX_LOCAL_IP : DEFAULT_RX_LOCAL_IP);
    if (args->remote_ip == NULL)
        args->remote_ip = is_ldp
                              ? (is_tx ? DEFAULT_LDP_TX_REMOTE_IP : DEFAULT_LDP_RX_REMOTE_IP)
                              : (is_tx ? DEFAULT_TX_REMOTE_IP : DEFAULT_RX_REMOTE_IP);
    if (args->service_id < 0)
        args->service_id = is_tx ? 502 : 501;
    if (args->main_lcore < 0)
        args->main_lcore = is_tx ? 30 : 24;
    if (args->bind_core < 0)
        args->bind_core = is_tx ? 31 : 25;
    if (args->bind_core == args->main_lcore)
    {
        fprintf(stderr, "bind-core must be different from main-lcore for fnp_lcore_launch\n");
        return -1;
    }
    if (strcmp(args->test, "rtt") == 0 && args->payload_bytes < sizeof(ping_payload_hdr_t))
    {
        fprintf(stderr, "RTT payload must be at least %zu bytes\n", sizeof(ping_payload_hdr_t));
        return -1;
    }

    return 0;
}

static int init_fnp(const demo_args_t *args)
{
    int lcores[1] = {args->bind_core};
    fnp_init_conf_t conf = {0};
    conf.main_lcore = args->main_lcore;
    conf.lcores = lcores;
    conf.num_lcores = 1;
    conf.id = (uint16_t)args->service_id;
    snprintf(conf.name, sizeof(conf.name), "node-perf-%s", args->mode);
    return fnp_init(&conf);
}

static int create_gtpu_socket(const demo_args_t *args, fnp_socket_t **socket)
{
    fnp_gtpu_socket_conf_t conf = {0};
    fsockaddr_init(&conf.local, FSOCKADDR_IPV4, args->local_ip, args->local_port);
    fsockaddr_init(&conf.remote, FSOCKADDR_IPV4, args->remote_ip, args->remote_port);
    conf.incoming_teid = args->incoming_teid;
    conf.outgoing_teid = args->outgoing_teid;
    return fnp_socket_create(fsocket_type_gtpu, &conf, socket);
}

static int run_rx(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_gtpu_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create RX socket failed: %d\n", ret);
        return 1;
    }

    const uint32_t rx_window_s = args->rx_window_s != 0 ? args->rx_window_s : args->duration_s;
    const uint64_t measure_ns = (uint64_t)rx_window_s * 1000000000ULL;
    const uint64_t start_ns = now_ns();
    const uint64_t end_ns = start_ns + measure_ns;
    const uint64_t offered = args->pps * args->duration_s;
    uint64_t received = 0;
    uint64_t bytes = 0;
    uint64_t last_print = start_ns;
    uint64_t last_print_received = 0;
    uint64_t first_rx_ns = 0;
    uint64_t last_rx_ns = 0;

    printf("RX start pps=%" PRIu64 " kpps=%.3f payload_bytes=%u duration_s=%u rx_window_s=%u expected=%" PRIu64 "\n",
           args->pps, to_kpps((double)args->pps), args->payload_bytes, args->duration_s, rx_window_s, offered);
    fflush(stdout);

    uint64_t now = start_ns;
    while (now < end_ns && received < offered)
    {
        fnp_mbuf_t *m = NULL;
        ret = fnp_socket_recv_mbuf(socket, &m);
        if (likely(ret == FNP_OK && m != NULL))
        {
            uint32_t len = (uint32_t)fnp_get_mbuf_len(m);
            ++received;
            bytes += len;
            fnp_free_mbuf(m);

            if (likely((received & PRINT_CHECK_MASK) != 0))
                continue;
        }

        now = now_ns();
        if (first_rx_ns == 0)
            first_rx_ns = now;
        last_rx_ns = now;
        if (unlikely(now - last_print >= 1000000000ULL))
        {
            double elapsed = (double)(now - start_ns) / 1e9;
            double interval = (double)(now - last_print) / 1e9;
            uint64_t interval_pkts = received - last_print_received;
            double pps = interval > 0.0 ? (double)interval_pkts / interval : 0.0;
            printf("RX %.0fs pkts=%" PRIu64 " rate=%.3f kpps\n",
                   elapsed, received, to_kpps(pps));
            last_print = now;
            last_print_received = received;
        }
    }

    const uint64_t finish_ns = now_ns();
    double elapsed = (double)(finish_ns - start_ns) / 1e9;
    double configured_pps = args->duration_s > 0 ? (double)received / (double)args->duration_s : 0.0;
    double active_elapsed = first_rx_ns != 0 && last_rx_ns > first_rx_ns ? (double)(last_rx_ns - first_rx_ns) / 1e9 : 0.0;
    double active_pps = active_elapsed > 0.0 ? (double)received / active_elapsed : 0.0;
    uint64_t lost = offered > received ? offered - received : 0;
    double pps = elapsed > 0.0 ? (double)received / elapsed : 0.0;
    printf("RX result received=%" PRIu64 " bytes=%" PRIu64
           " elapsed_s=%.9f kpps=%.3f configured_kpps=%.3f active_elapsed_s=%.9f active_kpps=%.3f"
           " offered=%" PRIu64 " lost=%" PRIu64 " loss_ratio=%.9f\n",
           received,
           bytes,
           elapsed,
           to_kpps(pps),
           to_kpps(configured_pps),
           active_elapsed,
           to_kpps(active_pps),
           offered,
           lost,
           offered > 0 ? (double)lost / (double)offered : 0.0);

    fnp_socket_close(socket);
    return 0;
}

static int send_one(fnp_socket_t *socket, uint32_t payload_bytes, uint64_t seq)
{
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
        return FNP_ERR_MBUF_ALLOC;

    uint8_t *data = fnp_mbuf_data(m);
    if (payload_bytes >= sizeof(seq))
        memcpy(data, &seq, sizeof(seq));
    fnp_mbuf_append_data(m, (int)payload_bytes);

    int ret = fnp_socket_send(socket, m);
    if (ret != FNP_OK)
        fnp_free_mbuf(m);
    return ret;
}

static int send_ping_one(fnp_socket_t *socket, uint32_t payload_bytes, uint64_t seq, uint64_t tx_ns)
{
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
        return FNP_ERR_MBUF_ALLOC;

    uint8_t *data = fnp_mbuf_data(m);
    if (payload_bytes >= sizeof(ping_payload_hdr_t))
    {
        ping_payload_hdr_t hdr = {
            .seq = seq,
            .tx_ns = tx_ns,
        };
        memcpy(data, &hdr, sizeof(hdr));
    }
    fnp_mbuf_append_data(m, (int)payload_bytes);

    int ret = fnp_socket_send(socket, m);
    if (ret != FNP_OK)
        fnp_free_mbuf(m);
    return ret;
}

static int run_pong(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_gtpu_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create PONG socket failed: %d\n", ret);
        return 1;
    }

    const bool has_deadline = args->rx_window_s != 0;
    const uint64_t end_ns = has_deadline ? now_ns() + (uint64_t)args->rx_window_s * 1000000000ULL : UINT64_MAX;
    uint64_t echoed = 0;
    uint64_t bad = 0;
    printf("RTT RX start rx_window_s=%s payload_bytes=%u\n",
           has_deadline ? "limited" : "unlimited",
           args->payload_bytes);
    fflush(stdout);

    while (now_ns() < end_ns)
    {
        fnp_mbuf_t *m = NULL;
        ret = fnp_socket_recv_mbuf(socket, &m);
        if (ret == FNP_OK && m != NULL)
        {
            uint32_t len = (uint32_t)fnp_get_mbuf_len(m);
            if (len < sizeof(ping_payload_hdr_t))
                ++bad;
            int send_ret = fnp_socket_send(socket, m);
            if (send_ret != FNP_OK)
                fnp_free_mbuf(m);
            else
                ++echoed;
        }
    }

    printf("RTT RX result echoed=%" PRIu64 " bad=%" PRIu64 "\n", echoed, bad);
    fnp_socket_close(socket);
    return 0;
}

static int run_ping(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_gtpu_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create PING socket failed: %d\n", ret);
        return 1;
    }

    FILE *fp = fopen(args->output, "w");
    if (fp == NULL)
    {
        fprintf(stderr, "open RTT TX output failed: %s\n", args->output);
        fnp_socket_close(socket);
        return 1;
    }
    setvbuf(fp, NULL, _IOFBF, RTT_CSV_BUFFER_SIZE);
    fprintf(fp, "seq,tx_ns,rx_ns\n");

    uint64_t target = args->pps * args->duration_s;
    uint64_t sent = 0;
    uint64_t received = 0;
    uint64_t errors = 0;
    uint64_t start_ns = now_ns();
    uint64_t last_print = start_ns;
    printf("PING start pps=%" PRIu64 " kpps=%.3f payload_bytes=%u duration_s=%u target=%" PRIu64 "\n",
           args->pps, to_kpps((double)args->pps), args->payload_bytes, args->duration_s, target);
    fflush(stdout);

    while (sent < target)
    {
        uint64_t now = now_ns();
        uint64_t should_send = ((now - start_ns) * args->pps) / 1000000000ULL;
        if (should_send > target)
            should_send = target;
        if (sent >= should_send)
        {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000};
            nanosleep(&ts, NULL);
            continue;
        }

        uint64_t tx_ns = now_ns();
        ret = send_ping_one(socket, args->payload_bytes, sent, tx_ns);
        if (ret != FNP_OK)
        {
            ++errors;
            ++sent;
            continue;
        }

        fnp_mbuf_t *m = NULL;
        ret = fnp_socket_recv_mbuf(socket, &m);
        uint64_t rx_ns = now_ns();
        if (ret == FNP_OK && m != NULL)
        {
            uint32_t len = (uint32_t)fnp_get_mbuf_len(m);
            uint8_t *data = fnp_mbuf_data(m);
            ping_payload_hdr_t hdr = {0};
            if (len >= sizeof(hdr))
                memcpy(&hdr, data, sizeof(hdr));
            if (len != args->payload_bytes || hdr.seq != sent || hdr.tx_ns != tx_ns)
                ++errors;
            else
            {
                fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", hdr.seq, tx_ns, rx_ns);
                ++received;
            }
            fnp_free_mbuf(m);
        }
        else
        {
            ++errors;
        }
        ++sent;

        now = now_ns();
        if (now - last_print >= 1000000000ULL)
        {
            printf("PING elapsed_s=%.3f sent=%" PRIu64 " received=%" PRIu64 " errors=%" PRIu64 "\n",
                   (double)(now - start_ns) / 1e9, sent, received, errors);
            fflush(stdout);
            last_print = now;
        }
    }

    if (fflush(fp) != 0)
        fprintf(stderr, "flush RTT CSV failed: errno=%d\n", errno);
    if (fsync(fileno(fp)) != 0)
        fprintf(stderr, "sync RTT CSV failed: errno=%d\n", errno);
    fclose(fp);
    double loss_ratio = target > 0 ? (double)(target - received) / (double)target : 0.0;
    printf("RTT result samples=%" PRIu64 " sent=%" PRIu64 " errors=%" PRIu64
           " loss_ratio=%.9f output=%s\n",
           received, sent, errors, loss_ratio, args->output);

    fnp_socket_close(socket);
    return 0;
}

static int run_tx(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_gtpu_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create TX socket failed: %d\n", ret);
        return 1;
    }

    uint64_t target = args->pps * args->duration_s;
    uint64_t attempts = 0;
    uint64_t ok = 0;
    uint64_t fail = 0;
    uint64_t full = 0;
    uint64_t alloc_fail = 0;
    uint64_t other_fail = 0;
    int last_err = FNP_OK;
    uint64_t start_ns = now_ns();
    uint64_t end_ns = start_ns + (uint64_t)args->duration_s * 1000000000ULL;
    uint64_t last_print = start_ns;
    uint64_t last_print_ok = 0;
    uint64_t last_print_fail = 0;

    printf("TX start pps=%" PRIu64 " kpps=%.3f payload_bytes=%u duration_s=%u target=%" PRIu64 "\n",
           args->pps, to_kpps((double)args->pps), args->payload_bytes, args->duration_s, target);
    fflush(stdout);

    while (attempts < target)
    {
        uint64_t now = now_ns();
        if (now >= end_ns && attempts >= target)
            break;

        uint64_t should_attempt = ((now - start_ns) * args->pps) / 1000000000ULL;
        if (should_attempt > target)
            should_attempt = target;

        if (attempts >= should_attempt)
        {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000};
            nanosleep(&ts, NULL);
            continue;
        }

        ret = send_one(socket, args->payload_bytes, attempts);
        ++attempts;
        if (ret == FNP_OK)
        {
            ++ok;
        }
        else
        {
            ++fail;
            last_err = ret;
            if (ret == FNP_ERR_FULL)
                ++full;
            else if (ret == FNP_ERR_MBUF_ALLOC)
                ++alloc_fail;
            else
                ++other_fail;
        }

        now = now_ns();
        if (unlikely((attempts & PRINT_CHECK_MASK) == 0 && now - last_print >= 1000000000ULL))
        {
            double elapsed = (double)(now - start_ns) / 1e9;
            double interval = (double)(now - last_print) / 1e9;
            uint64_t interval_ok = ok - last_print_ok;
            uint64_t interval_fail = fail - last_print_fail;
            double ok_pps = interval > 0.0 ? (double)interval_ok / interval : 0.0;
            printf("TX %.0fs ok=%" PRIu64 " fail=%" PRIu64 " rate=%.3f kpps fail_delta=%" PRIu64 "\n",
                   elapsed, ok, fail, to_kpps(ok_pps), interval_fail);
            fflush(stdout);
            last_print = now;
            last_print_ok = ok;
            last_print_fail = fail;
        }
    }

    uint64_t finish_ns = now_ns();
    double elapsed = (double)(finish_ns - start_ns) / 1e9;
    double attempt_pps = elapsed > 0.0 ? (double)attempts / elapsed : 0.0;
    double ok_pps = elapsed > 0.0 ? (double)ok / elapsed : 0.0;
    printf("TX result attempts=%" PRIu64 " ok=%" PRIu64 " fail=%" PRIu64
           " tx_ring_full=%" PRIu64 " mbuf_alloc_fail=%" PRIu64 " other_fail=%" PRIu64
           " last_err=%d elapsed_s=%.9f attempt_kpps=%.3f ok_kpps=%.3f\n",
           attempts,
           ok,
           fail,
           full,
           alloc_fail,
           other_fail,
           last_err,
           elapsed,
           to_kpps(attempt_pps),
           to_kpps(ok_pps));

    fnp_socket_close(socket);
    return 0;
}

static int run_on_fnp_lcore(void *arg)
{
    demo_lcore_job_t *job = (demo_lcore_job_t *)arg;
    const demo_args_t *args = job->args;
    int ret = 0;

    printf("APP_LCORE lcore=%u sched_cpu=%d\n", fnp_lcore_id(), sched_getcpu());
    fflush(stdout);

    if (strcmp(args->test, "rtt") == 0 && strcmp(args->mode, "rx") == 0)
        ret = run_pong(args);
    else if (strcmp(args->test, "rtt") == 0)
        ret = run_ping(args);
    else if (strcmp(args->mode, "rx") == 0)
        ret = run_rx(args);
    else
        ret = run_tx(args);

    job->ret = ret;
    atomic_store_explicit(&job->done, true, memory_order_release);
    return ret;
}

int main(int argc, char **argv)
{
    demo_args_t args;
    if (parse_args(argc, argv, &args) != 0)
        return 1;

    int ret = init_fnp(&args);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_init failed: %d\n", ret);
        return 1;
    }

    demo_lcore_job_t job = {
        .args = &args,
        .done = ATOMIC_VAR_INIT(false),
        .ret = 0,
    };
    ret = fnp_lcore_launch((unsigned)args.bind_core, run_on_fnp_lcore, &job);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_lcore_launch failed: lcore=%d ret=%d\n", args.bind_core, ret);
        return 1;
    }

    while (!atomic_load_explicit(&job.done, memory_order_acquire))
    {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&ts, NULL);
    }

    ret = fnp_lcore_wait((unsigned)args.bind_core);
    if (ret < 0)
    {
        fprintf(stderr, "fnp_lcore_wait failed: lcore=%d ret=%d\n", args.bind_core, ret);
        return 1;
    }
    return job.ret != 0 ? job.ret : ret;
}
