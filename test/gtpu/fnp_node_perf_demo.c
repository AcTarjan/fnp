#define _GNU_SOURCE

#include "fnp.h"
#include "fnp_error.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PPS 1000000ULL
#define DEFAULT_KPPS 1000.0
#define DEFAULT_PAYLOAD_BYTES 256U
#define DEFAULT_DURATION_S 20U
#define DEFAULT_DRAIN_S 5U
#define DEFAULT_LOCAL_PORT 2152U
#define DEFAULT_INCOMING_TEID 0x1001U
#define DEFAULT_OUTGOING_TEID 0x1001U

typedef struct demo_args {
    const char *mode;
    const char *local_ip;
    const char *remote_ip;
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

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void bind_current_thread(int core)
{
    if (core < 0)
        return;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core, &set);
    int ret = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (ret != 0)
        fprintf(stderr, "bind CPU %d failed: ret=%d errno=%d\n", core, ret, errno);
    else
        printf("AFFINITY core=%d sched_cpu=%d\n", core, sched_getcpu());
}

static double to_kpps(double pps)
{
    return pps / 1000.0;
}

static void print_payload_sample(uint64_t packet_index, uint64_t seq, const uint8_t *data, uint32_t len)
{
    const uint32_t sample_len = len < 16 ? len : 16;
    printf("RX payload sample packet=%" PRIu64 " len=%u seq=%" PRIu64 " bytes=", packet_index, len, seq);
    for (uint32_t i = 0; i < sample_len; ++i)
        printf("%02x%s", data[i], i + 1 == sample_len ? "" : " ");
    printf("\n");
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
            "Usage: %s --mode rx|tx --local-ip IP --remote-ip IP [options]\n"
            "Options:\n"
            "  --kpps N                 offered rate in kpps for TX and RX drop baseline, default %.3f\n"
            "  --pps N                  offered packet rate for TX and RX drop baseline\n"
            "  --payload-bytes N        payload size, default %u\n"
            "  --duration-s N           measured send/receive window, default %u\n"
            "  --drain-s N              extra RX drain time, default %u\n"
            "  --rx-window-s N          total RX wall-clock window; default duration+drain\n"
            "  --local-port N           local GTP-U UDP port, default %u\n"
            "  --remote-port N          remote GTP-U UDP port, default %u\n"
            "  --incoming-teid N        incoming TEID, default %#x\n"
            "  --outgoing-teid N        outgoing TEID, default %#x\n"
            "  --service-id N           FNP frontend service id\n"
            "  --main-lcore N           DPDK secondary main lcore\n"
            "  --bind-core N            bind application thread after fnp_init\n",
            prog,
            DEFAULT_KPPS,
            DEFAULT_PAYLOAD_BYTES,
            DEFAULT_DURATION_S,
            DEFAULT_DRAIN_S,
            DEFAULT_LOCAL_PORT,
            DEFAULT_LOCAL_PORT,
            DEFAULT_INCOMING_TEID,
            DEFAULT_OUTGOING_TEID);
}

static int parse_args(int argc, char **argv, demo_args_t *args)
{
    *args = (demo_args_t){
        .mode = NULL,
        .local_ip = NULL,
        .remote_ip = NULL,
        .local_port = DEFAULT_LOCAL_PORT,
        .remote_port = DEFAULT_LOCAL_PORT,
        .incoming_teid = DEFAULT_INCOMING_TEID,
        .outgoing_teid = DEFAULT_OUTGOING_TEID,
        .pps = DEFAULT_PPS,
        .payload_bytes = DEFAULT_PAYLOAD_BYTES,
        .duration_s = DEFAULT_DURATION_S,
        .drain_s = DEFAULT_DRAIN_S,
        .rx_window_s = 0,
        .service_id = 501,
        .main_lcore = 0,
        .bind_core = -1,
    };

    for (int i = 1; i < argc; ++i) {
        const char *opt = argv[i];
        const char *val = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(opt, "--help") == 0) {
            usage(argv[0]);
            exit(0);
        } else if (val == NULL) {
            usage(argv[0]);
            return -1;
        } else if (strcmp(opt, "--mode") == 0) {
            args->mode = val;
            ++i;
        } else if (strcmp(opt, "--local-ip") == 0) {
            args->local_ip = val;
            ++i;
        } else if (strcmp(opt, "--remote-ip") == 0) {
            args->remote_ip = val;
            ++i;
        } else if (strcmp(opt, "--pps") == 0) {
            if (parse_u64(val, &args->pps) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--kpps") == 0) {
            double kpps = 0.0;
            if (parse_double(val, &kpps) != 0)
                return -1;
            args->pps = (uint64_t)(kpps * 1000.0 + 0.5);
            ++i;
        } else if (strcmp(opt, "--payload-bytes") == 0) {
            if (parse_u32(val, &args->payload_bytes) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--duration-s") == 0) {
            if (parse_u32(val, &args->duration_s) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--drain-s") == 0) {
            if (parse_u32(val, &args->drain_s) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--rx-window-s") == 0) {
            if (parse_u32(val, &args->rx_window_s) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--local-port") == 0) {
            uint32_t port = 0;
            if (parse_u32(val, &port) != 0 || port > UINT16_MAX)
                return -1;
            args->local_port = (uint16_t)port;
            ++i;
        } else if (strcmp(opt, "--remote-port") == 0) {
            uint32_t port = 0;
            if (parse_u32(val, &port) != 0 || port > UINT16_MAX)
                return -1;
            args->remote_port = (uint16_t)port;
            ++i;
        } else if (strcmp(opt, "--incoming-teid") == 0) {
            if (parse_u32(val, &args->incoming_teid) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--outgoing-teid") == 0) {
            if (parse_u32(val, &args->outgoing_teid) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--service-id") == 0) {
            if (parse_int(val, &args->service_id) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--main-lcore") == 0) {
            if (parse_int(val, &args->main_lcore) != 0)
                return -1;
            ++i;
        } else if (strcmp(opt, "--bind-core") == 0) {
            if (parse_int(val, &args->bind_core) != 0)
                return -1;
            ++i;
        } else {
            usage(argv[0]);
            return -1;
        }
    }

    if (args->mode == NULL || args->local_ip == NULL || args->remote_ip == NULL ||
        (strcmp(args->mode, "rx") != 0 && strcmp(args->mode, "tx") != 0) ||
        args->pps == 0 || args->payload_bytes == 0 ||
        args->incoming_teid == 0 || args->outgoing_teid == 0) {
        usage(argv[0]);
        return -1;
    }

    return 0;
}

static int init_fnp(const demo_args_t *args)
{
    int lcores[1] = {args->main_lcore};
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
    if (ret != FNP_OK) {
        fprintf(stderr, "create RX socket failed: %d\n", ret);
        return 1;
    }

    const uint32_t rx_window_s = args->rx_window_s != 0 ? args->rx_window_s : args->duration_s + args->drain_s;
    const uint64_t measure_ns = (uint64_t)rx_window_s * 1000000000ULL;
    const uint64_t start_ns = now_ns();
    const uint64_t end_ns = start_ns + measure_ns;
    const uint64_t offered = args->pps * args->duration_s;
    uint64_t received = 0;
    uint64_t bytes = 0;
    uint64_t last_print = start_ns;
    uint64_t first_rx_ns = 0;
    uint64_t last_rx_ns = 0;
    uint64_t seq_errors = 0;
    uint64_t len_errors = 0;
    uint64_t payload_errors = 0;
    uint64_t first_seq = UINT64_MAX;
    uint64_t last_seq = UINT64_MAX;
    uint64_t expected_seq = UINT64_MAX;

    printf("RX start pps=%" PRIu64 " kpps=%.3f payload_bytes=%u duration_s=%u drain_s=%u rx_window_s=%u expected=%" PRIu64 "\n",
           args->pps, to_kpps((double)args->pps), args->payload_bytes, args->duration_s, args->drain_s, rx_window_s, offered);
    fflush(stdout);

    while (now_ns() < end_ns && received < offered) {
        fnp_mbuf_t *m = NULL;
        ret = fnp_socket_recv_mbuf(socket, &m);
        if (ret == FNP_OK && m != NULL) {
            uint64_t rx_ns = now_ns();
            if (first_rx_ns == 0)
                first_rx_ns = rx_ns;
            last_rx_ns = rx_ns;
            uint32_t len = (uint32_t)fnp_get_mbuf_len(m);
            uint8_t *data = fnp_mbuf_data(m);
            uint64_t seq = UINT64_MAX;
            if (len >= sizeof(seq))
                memcpy(&seq, data, sizeof(seq));
            if (len != args->payload_bytes)
                ++len_errors;
            if (seq != UINT64_MAX) {
                if (first_seq == UINT64_MAX) {
                    first_seq = seq;
                    expected_seq = seq;
                }
                if (seq != expected_seq) {
                    ++seq_errors;
                    expected_seq = seq;
                }
                last_seq = seq;
                ++expected_seq;
            } else {
                ++seq_errors;
            }
            for (uint32_t i = sizeof(seq); i < len; ++i) {
                if (data[i] != 0xa5) {
                    ++payload_errors;
                    break;
                }
            }
            if (received < 8)
                print_payload_sample(received, seq, data, len);
            ++received;
            bytes += len;
            fnp_free_mbuf(m);
        }

        uint64_t now = now_ns();
        if (now - last_print >= 1000000000ULL) {
            double elapsed = (double)(now - start_ns) / 1e9;
            double pps = elapsed > 0.0 ? (double)received / elapsed : 0.0;
            printf("RX elapsed_s=%.3f received=%" PRIu64 " kpps=%.3f\n",
                   elapsed, received, to_kpps(pps));
            fflush(stdout);
            last_print = now;
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
           " offered=%" PRIu64 " lost=%" PRIu64 " loss_ratio=%.9f"
           " seq_errors=%" PRIu64 " len_errors=%" PRIu64 " payload_errors=%" PRIu64
           " first_seq=%" PRIu64 " last_seq=%" PRIu64 "\n",
           received,
           bytes,
           elapsed,
           to_kpps(pps),
           to_kpps(configured_pps),
           active_elapsed,
           to_kpps(active_pps),
           offered,
           lost,
           offered > 0 ? (double)lost / (double)offered : 0.0,
           seq_errors,
           len_errors,
           payload_errors,
           first_seq,
           last_seq);

    fnp_socket_close(socket);
    return 0;
}

static int send_one(fnp_socket_t *socket, uint32_t payload_bytes, uint64_t seq)
{
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
        return FNP_ERR_MBUF_ALLOC;

    uint8_t *data = fnp_mbuf_data(m);
    memset(data, 0xa5, payload_bytes);
    if (payload_bytes >= sizeof(seq))
        memcpy(data, &seq, sizeof(seq));
    fnp_mbuf_append_data(m, (int)payload_bytes);

    int ret = fnp_socket_send(socket, m);
    if (ret != FNP_OK)
        fnp_free_mbuf(m);
    return ret;
}

static int run_tx(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_gtpu_socket(args, &socket);
    if (ret != FNP_OK) {
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

    printf("TX start pps=%" PRIu64 " kpps=%.3f payload_bytes=%u duration_s=%u target=%" PRIu64 "\n",
           args->pps, to_kpps((double)args->pps), args->payload_bytes, args->duration_s, target);
    fflush(stdout);

    while (attempts < target) {
        uint64_t now = now_ns();
        if (now >= end_ns && attempts >= target)
            break;

        uint64_t should_attempt = ((now - start_ns) * args->pps) / 1000000000ULL;
        if (should_attempt > target)
            should_attempt = target;

        if (attempts >= should_attempt) {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000};
            nanosleep(&ts, NULL);
            continue;
        }

        ret = send_one(socket, args->payload_bytes, attempts);
        ++attempts;
        if (ret == FNP_OK) {
            ++ok;
        } else {
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
        if (now - last_print >= 1000000000ULL) {
            double elapsed = (double)(now - start_ns) / 1e9;
            double ok_pps = elapsed > 0.0 ? (double)ok / elapsed : 0.0;
            printf("TX elapsed_s=%.3f attempts=%" PRIu64 " ok=%" PRIu64
                   " fail=%" PRIu64 " tx_ring_full=%" PRIu64 " mbuf_alloc_fail=%" PRIu64
                   " other_fail=%" PRIu64 " ok_kpps=%.3f\n",
                   elapsed, attempts, ok, fail, full, alloc_fail, other_fail, to_kpps(ok_pps));
            fflush(stdout);
            last_print = now;
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

int main(int argc, char **argv)
{
    demo_args_t args;
    if (parse_args(argc, argv, &args) != 0)
        return 1;

    int ret = init_fnp(&args);
    if (ret != FNP_OK) {
        fprintf(stderr, "fnp_init failed: %d\n", ret);
        return 1;
    }

    bind_current_thread(args.bind_core);

    if (strcmp(args.mode, "rx") == 0)
        return run_rx(&args);
    return run_tx(&args);
}
