#define _GNU_SOURCE

#include "fnp.h"
#include "fnp_error.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── defaults ────────────────────────────────────────────────────────── */
#define DEFAULT_KPPS 1000.0
#define DEFAULT_PAYLOAD_BYTES 256U
#define DEFAULT_DURATION_S 60U
#define DEFAULT_LOCAL_PORT 2152U
#define DEFAULT_TEID 0x1001U
#define DEFAULT_TRIM_S 5U
#define DEFAULT_RTT_OUTPUT "/tmp/rtt.csv"

/* cross-node path: TX on .5, RX on .3 */
#define CROSS_TX_IP "192.168.100.5"
#define CROSS_RX_IP "192.168.100.3"
/* ldp same-node path: TX on .2, RX on .3 */
#define LDP_TX_IP "192.168.100.2"
#define LDP_RX_IP "192.168.100.3"

#define RTT_CSV_BUF (16U * 1024U * 1024U)
#define PRINT_MASK 4095U

/* ── packet header (seq + tx timestamp) ──────────────────────────────── */
typedef struct __attribute__((packed)) pkt_hdr
{
    uint64_t seq;
    uint64_t tx_ns;
} pkt_hdr_t;

/* ── run modes ───────────────────────────────────────────────────────── */
typedef enum
{
    MODE_TX_PPS,
    MODE_RX_PPS,
    MODE_TX_RTT,
    MODE_RX_RTT
} run_mode_t;

typedef struct demo_args
{
    run_mode_t mode;
    const char *path;
    const char *local_ip;
    const char *remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t teid;
    uint64_t pps;
    uint32_t payload_bytes;
    uint32_t duration_s;
    uint32_t trim_s;
    const char *output;
    int service_id;
    int main_lcore;
    int bind_core;
    int rtt_rx_core; /* second lcore for tx-rtt recording */
} demo_args_t;

/* ── RTT two-lcore shared state ──────────────────────────────────────── */
typedef struct rtt_shared
{
    const demo_args_t *args;
    fnp_socket_t *socket;     /* created by TX lcore; read by RX lcore after socket_ready */
    atomic_bool socket_ready; /* TX lcore sets after socket create */
    uint64_t tx_ok;           /* written before tx_done (release); read after tx_done (acquire) */
    atomic_bool tx_done;
    atomic_bool rx_done;
} rtt_shared_t;

typedef struct lcore_job
{
    void *ctx;
    atomic_bool done;
    int ret;
} lcore_job_t;

/* ── utilities ───────────────────────────────────────────────────────── */
static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
static double to_kpps(double pps) { return pps / 1000.0; }
static int cmp_u64(const void *a, const void *b)
{
    const uint64_t va = *(const uint64_t *)a, vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}
static double pct_u64(const uint64_t *v, size_t n, double p)
{
    if (n == 0)
        return 0.0;
    if (n == 1)
        return (double)v[0];
    double pos = (p / 100.0) * (double)(n - 1);
    size_t lo = (size_t)pos, hi = lo + 1 < n ? lo + 1 : lo;
    double f = pos - (double)lo;
    return (double)v[lo] * (1.0 - f) + (double)v[hi] * f;
}

static int parse_double(const char *s, double *out)
{
    char *e = NULL;
    double v = strtod(s, &e);
    if (e == s || *e != '\0' || v < 0.0)
        return -1;
    *out = v;
    return 0;
}
static int parse_u32(const char *s, uint32_t *out)
{
    char *e = NULL;
    unsigned long long v = strtoull(s, &e, 10);
    if (e == s || *e != '\0' || v > UINT32_MAX)
        return -1;
    *out = (uint32_t)v;
    return 0;
}
static int parse_int(const char *s, int *out)
{
    char *e = NULL;
    long v = strtol(s, &e, 10);
    if (e == s || *e != '\0')
        return -1;
    *out = (int)v;
    return 0;
}

/* ── create GTP-U socket ─────────────────────────────────────────────── */
static int create_socket(const demo_args_t *args, fnp_socket_t **out)
{
    fnp_gtpu_socket_conf_t c = {0};
    fsockaddr_init(&c.local, FSOCKADDR_IPV4, args->local_ip, args->local_port);
    fsockaddr_init(&c.remote, FSOCKADDR_IPV4, args->remote_ip, args->remote_port);
    c.incoming_teid = args->teid;
    c.outgoing_teid = args->teid;
    return fnp_socket_create(fsocket_type_gtpu, &c, out);
}

/* ── send one packet with seq+tx_ns header ───────────────────────────── */
static int send_pkt(fnp_socket_t *s, uint32_t len, uint64_t seq, uint64_t tx_ns)
{
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (!m)
        return FNP_ERR_MBUF_ALLOC;
    if (len >= sizeof(pkt_hdr_t))
    {
        pkt_hdr_t h = {.seq = seq, .tx_ns = tx_ns};
        memcpy(fnp_mbuf_data(m), &h, sizeof(h));
    }
    fnp_mbuf_append_data(m, (int)len);
    int r = fnp_socket_send(s, m);
    if (r != FNP_OK)
        fnp_free_mbuf(m);
    return r;
}

/* ══════════════════════════════════════════════════════════════════════
 * rx-pps: receive indefinitely, print per-second RX kpps
 * ══════════════════════════════════════════════════════════════════════ */
static int run_rx_pps(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create socket failed: %d\n", ret);
        return 1;
    }

    uint64_t start_ns = now_ns();
    uint64_t last_ns = start_ns;
    uint64_t received = 0;
    uint64_t last_recv = 0;

    printf("RX-PPS start payload_bytes=%u\n", args->payload_bytes);
    fflush(stdout);

    for (;;)
    {
        fnp_mbuf_t *m = NULL;
        ret = fnp_socket_recv_mbuf(socket, &m);
        if (ret == FNP_OK && m != NULL)
        {
            ++received;
            fnp_free_mbuf(m);
        }
        uint64_t now = now_ns();
        if (now - last_ns >= 1000000000ULL)
        {
            double interval = (double)(now - last_ns) / 1e9;
            double pps = interval > 0.0 ? (double)(received - last_recv) / interval : 0.0;
            printf("elapsed_s=%.0f received=%" PRIu64 " rx_kpps=%.3f\n",
                   (double)(now - start_ns) / 1e9, received, to_kpps(pps));
            fflush(stdout);
            last_ns = now;
            last_recv = received;
        }
    }
    /* unreachable; process killed by signal */
}

/* ══════════════════════════════════════════════════════════════════════
 * tx-pps: send at target kpps for duration_s
 * ══════════════════════════════════════════════════════════════════════ */
static int run_tx_pps(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create socket failed: %d\n", ret);
        return 1;
    }

    const uint64_t target = args->pps * args->duration_s;
    uint64_t attempts = 0, ok = 0, fail = 0;
    uint64_t start_ns = now_ns();
    uint64_t last_ns = start_ns;
    uint64_t last_ok = 0;

    printf("TX-PPS start kpps=%.3f payload_bytes=%u duration_s=%u target=%" PRIu64 "\n",
           to_kpps((double)args->pps), args->payload_bytes, args->duration_s, target);
    fflush(stdout);

    while (attempts < target)
    {
        uint64_t now = now_ns();
        uint64_t should = ((now - start_ns) * args->pps) / 1000000000ULL;
        if (should > target)
            should = target;
        if (attempts >= should)
            continue;

        ret = send_pkt(socket, args->payload_bytes, attempts, 0);
        ++attempts;
        if (ret == FNP_OK)
            ++ok;
        else
            ++fail;

        if (unlikely((attempts & PRINT_MASK) == 0))
        {
            now = now_ns();
            if (now - last_ns >= 1000000000ULL)
            {
                double interval = (double)(now - last_ns) / 1e9;
                double rate = interval > 0.0 ? (double)(ok - last_ok) / interval : 0.0;
                printf("TX-PPS elapsed_s=%.0f ok=%" PRIu64 " fail=%" PRIu64 " rate_kpps=%.3f\n",
                       (double)(now - start_ns) / 1e9, ok, fail, to_kpps(rate));
                fflush(stdout);
                last_ns = now;
                last_ok = ok;
            }
        }
    }

    uint64_t fin = now_ns();
    double elapsed = (double)(fin - start_ns) / 1e9;
    printf("TX-PPS done sent=%" PRIu64 " ok=%" PRIu64 " fail=%" PRIu64 " tx_kpps=%.3f\n",
           attempts, ok, fail, to_kpps(elapsed > 0.0 ? (double)ok / elapsed : 0.0));
    fnp_socket_close(socket);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * rx-rtt: echo all received packets back, run indefinitely
 * ══════════════════════════════════════════════════════════════════════ */
static int run_rx_rtt(const demo_args_t *args)
{
    fnp_socket_t *socket = NULL;
    int ret = create_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "create socket failed: %d\n", ret);
        return 1;
    }

    uint64_t echoed = 0, bad = 0;
    printf("RTT-RX start (echo forever) payload_bytes=%u\n", args->payload_bytes);
    fflush(stdout);

    for (;;)
    {
        fnp_mbuf_t *m = NULL;
        ret = fnp_socket_recv_mbuf(socket, &m);
        if (ret != FNP_OK || m == NULL)
            continue;
        uint32_t len = (uint32_t)fnp_get_mbuf_len(m);
        if (len < sizeof(pkt_hdr_t))
            ++bad;
        ret = fnp_socket_send(socket, m);
        if (ret != FNP_OK)
        {
            fnp_free_mbuf(m);
        }
        else
        {
            ++echoed;
        }
        if (unlikely(echoed % 100000 == 0 && echoed > 0))
        {
            printf("RTT-RX echoed=%" PRIu64 " bad=%" PRIu64 "\n", echoed, bad);
            fflush(stdout);
        }
    }
    /* unreachable; process killed by signal */
}

/* ══════════════════════════════════════════════════════════════════════
 * tx-rtt TX lcore: send packets at rate, then signal RX lcore
 * ══════════════════════════════════════════════════════════════════════ */
static int rtt_tx_lcore(void *arg)
{
    lcore_job_t *job = (lcore_job_t *)arg;
    rtt_shared_t *sh = (rtt_shared_t *)job->ctx;
    const demo_args_t *args = sh->args;

    fprintf(stderr, "RTT-TX lcore=%u cpu=%d\n", fnp_lcore_id(), sched_getcpu());

    /* create socket and publish to RX lcore */
    fnp_socket_t *socket = NULL;
    int ret = create_socket(args, &socket);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "RTT-TX: create socket failed: %d\n", ret);
        job->ret = 1;
        atomic_store_explicit(&job->done, true, memory_order_release);
        return 1;
    }
    sh->socket = socket;
    atomic_store_explicit(&sh->socket_ready, true, memory_order_release);

    const uint64_t target = (uint64_t)args->pps * args->duration_s;
    const uint64_t pps = args->pps;
    const uint32_t plen = args->payload_bytes;
    uint64_t sent = 0, ok = 0, fail = 0;
    uint64_t start_ns = now_ns();
    uint64_t last_ns = start_ns;
    uint64_t last_ok = 0;

    printf("RTT-TX send start kpps=%.3f payload=%u target=%" PRIu64 "\n",
           to_kpps((double)pps), plen, target);
    fflush(stdout);

    while (sent < target)
    {
        uint64_t now = now_ns();
        uint64_t should = ((now - start_ns) * pps) / 1000000000ULL;
        if (should > target)
            should = target;
        if (sent >= should)
            continue;

        uint64_t tx_ns = now_ns();
        ret = send_pkt(socket, plen, sent, tx_ns);
        ++sent;
        if (ret == FNP_OK)
            ++ok;
        else
            ++fail;

        if (unlikely((sent & PRINT_MASK) == 0))
        {
            now = now_ns();
            if (now - last_ns >= 1000000000ULL)
            {
                double interval = (double)(now - last_ns) / 1e9;
                double rate = interval > 0.0 ? (double)(ok - last_ok) / interval : 0.0;
                printf("RTT-TX elapsed_s=%.0f sent=%" PRIu64 " ok=%" PRIu64 " kpps=%.3f\n",
                       (double)(now - start_ns) / 1e9, sent, ok, to_kpps(rate));
                fflush(stdout);
                last_ns = now;
                last_ok = ok;
            }
        }
    }

    /* signal done; release ordering ensures tx_ok is visible to RX lcore */
    sh->tx_ok = ok;
    atomic_store_explicit(&sh->tx_done, true, memory_order_release);

    printf("RTT-TX sent=%" PRIu64 " ok=%" PRIu64 " fail=%" PRIu64 " – waiting for RX drain...\n",
           sent, ok, fail);
    fflush(stdout);

    /* wait up to 30s for RX lcore to finish draining */
    uint64_t wait_end = now_ns() + 30ULL * 1000000000ULL;
    while (!atomic_load_explicit(&sh->rx_done, memory_order_acquire) && now_ns() < wait_end)
    {
        struct timespec ts = {0, 10000000L};
        nanosleep(&ts, NULL);
    }

    job->ret = 0;
    atomic_store_explicit(&job->done, true, memory_order_release);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * tx-rtt RX lcore: receive echoes, record rtt_ns to CSV
 * ══════════════════════════════════════════════════════════════════════ */
static int rtt_rx_lcore(void *arg)
{
    lcore_job_t *job = (lcore_job_t *)arg;
    rtt_shared_t *sh = (rtt_shared_t *)job->ctx;
    const demo_args_t *args = sh->args;

    fprintf(stderr, "RTT-RX lcore=%u cpu=%d\n", fnp_lcore_id(), sched_getcpu());

    /* wait for TX lcore to create and publish socket */
    while (!atomic_load_explicit(&sh->socket_ready, memory_order_acquire))
    {
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
    fnp_socket_t *socket = sh->socket;

    FILE *fp = fopen(args->output, "w");
    if (!fp)
    {
        fprintf(stderr, "RTT-RX: open output failed: %s (errno=%d)\n", args->output, errno);
        job->ret = 1;
        atomic_store_explicit(&sh->rx_done, true, memory_order_release);
        atomic_store_explicit(&job->done, true, memory_order_release);
        return 1;
    }
    setvbuf(fp, NULL, _IOFBF, RTT_CSV_BUF);
    fprintf(fp, "seq,rtt_ns\n");

    uint64_t received = 0;
    uint64_t bad = 0;
    uint64_t drain_end = UINT64_MAX;

    for (;;)
    {
        bool done = atomic_load_explicit(&sh->tx_done, memory_order_acquire);
        if (done)
        {
            if (drain_end == UINT64_MAX)
                drain_end = now_ns() + 10ULL * 1000000000ULL; /* 10s drain window */
            if (received >= sh->tx_ok || now_ns() >= drain_end)
                break;
        }

        fnp_mbuf_t *m = NULL;
        int ret = fnp_socket_recv_mbuf(socket, &m);
        if (ret != FNP_OK || m == NULL)
            continue;

        uint64_t rx_ns = now_ns();
        uint32_t len = (uint32_t)fnp_get_mbuf_len(m);
        if (len >= sizeof(pkt_hdr_t))
        {
            pkt_hdr_t h = {0};
            memcpy(&h, fnp_mbuf_data(m), sizeof(h));
            if (h.tx_ns != 0 && rx_ns >= h.tx_ns)
                fprintf(fp, "%" PRIu64 ",%" PRIu64 "\n", h.seq, rx_ns - h.tx_ns);
            else
                ++bad;
        }
        else
        {
            ++bad;
        }
        fnp_free_mbuf(m);
        ++received;
    }

    if (fflush(fp) != 0)
        fprintf(stderr, "flush RTT CSV failed: errno=%d\n", errno);
    if (fsync(fileno(fp)) != 0)
        fprintf(stderr, "sync RTT CSV failed: errno=%d\n", errno);
    fclose(fp);

    uint64_t lost = sh->tx_ok > received ? sh->tx_ok - received : 0;
    double loss = sh->tx_ok > 0 ? (double)lost / (double)sh->tx_ok : 0.0;
    printf("RTT-RX done received=%" PRIu64 " bad=%" PRIu64 " loss_rate=%.6f output=%s\n",
           received, bad, loss, args->output);
    fflush(stdout);

    atomic_store_explicit(&sh->rx_done, true, memory_order_release);
    job->ret = 0;
    atomic_store_explicit(&job->done, true, memory_order_release);
    return 0;
}

/* ── single-lcore dispatch for pps/rx-rtt modes ─────────────────────── */
static int single_lcore_func(void *arg)
{
    lcore_job_t *job = (lcore_job_t *)arg;
    demo_args_t *args = (demo_args_t *)job->ctx;
    int ret;

    fprintf(stderr, "APP_LCORE lcore=%u cpu=%d mode=%d\n",
            fnp_lcore_id(), sched_getcpu(), (int)args->mode);

    switch (args->mode)
    {
    case MODE_TX_PPS:
        ret = run_tx_pps(args);
        break;
    case MODE_RX_PPS:
        ret = run_rx_pps(args);
        break;
    case MODE_RX_RTT:
        ret = run_rx_rtt(args);
        break;
    default:
        ret = 1;
        break;
    }

    job->ret = ret;
    atomic_store_explicit(&job->done, true, memory_order_release);
    return ret;
}

/* ── usage ───────────────────────────────────────────────────────────── */
static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --mode tx-pps|rx-pps|tx-rtt|rx-rtt [options]\n"
            "Options:\n"
            "  --mode tx-pps|rx-pps|tx-rtt|rx-rtt\n"
            "  --kpps N            offered rate kpps (TX modes), default %.3f\n"
            "  --payload-bytes N   payload size bytes, default %u\n"
            "  --duration-s N      TX window seconds, default %u\n"
            "  --path cross|ldp    IP defaults; default ldp\n"
            "  --local-ip IP       override local IP\n"
            "  --remote-ip IP      override remote IP\n"
            "  --local-port N      GTP-U local UDP port, default %u\n"
            "  --remote-port N     GTP-U remote UDP port, default %u\n"
            "  --teid N            GTP-U TEID (in/out), default %#x\n"
            "  --output FILE       RTT CSV output (tx-rtt), default %s\n"
            "  --trim-s N          trim head/tail seconds (info only), default %u\n"
            "  --service-id N      FNP frontend service id\n"
            "  --main-lcore N      DPDK secondary main lcore\n"
            "  --bind-core N       TX/echo lcore (bind-core != main-lcore)\n"
            "  --rtt-rx-core N     second RX recording lcore (tx-rtt only)\n",
            prog,
            DEFAULT_KPPS, DEFAULT_PAYLOAD_BYTES, DEFAULT_DURATION_S,
            DEFAULT_LOCAL_PORT, DEFAULT_LOCAL_PORT, DEFAULT_TEID,
            DEFAULT_RTT_OUTPUT, DEFAULT_TRIM_S);
}

/* ── argument parser ─────────────────────────────────────────────────── */
static int parse_args(int argc, char **argv, demo_args_t *args)
{
    *args = (demo_args_t){
        .mode = (run_mode_t)-1,
        .path = NULL,
        .local_ip = NULL,
        .remote_ip = NULL,
        .local_port = DEFAULT_LOCAL_PORT,
        .remote_port = DEFAULT_LOCAL_PORT,
        .teid = DEFAULT_TEID,
        .pps = (uint64_t)(DEFAULT_KPPS * 1000.0 + 0.5),
        .payload_bytes = DEFAULT_PAYLOAD_BYTES,
        .duration_s = DEFAULT_DURATION_S,
        .trim_s = DEFAULT_TRIM_S,
        .output = DEFAULT_RTT_OUTPUT,
        .service_id = -1,
        .main_lcore = -1,
        .bind_core = -1,
        .rtt_rx_core = -1,
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
        if (val == NULL)
        {
            usage(argv[0]);
            return -1;
        }

        if (strcmp(opt, "--mode") == 0)
        {
            if (strcmp(val, "tx-pps") == 0)
                args->mode = MODE_TX_PPS;
            else if (strcmp(val, "rx-pps") == 0)
                args->mode = MODE_RX_PPS;
            else if (strcmp(val, "tx-rtt") == 0)
                args->mode = MODE_TX_RTT;
            else if (strcmp(val, "rx-rtt") == 0)
                args->mode = MODE_RX_RTT;
            else
            {
                fprintf(stderr, "invalid mode: %s\n", val);
                return -1;
            }
        }
        else if (strcmp(opt, "--kpps") == 0)
        {
            double kpps = 0.0;
            if (parse_double(val, &kpps) != 0 || kpps <= 0.0)
                return -1;
            args->pps = (uint64_t)(kpps * 1000.0 + 0.5);
        }
        else if (strcmp(opt, "--payload-bytes") == 0)
        {
            if (parse_u32(val, &args->payload_bytes) != 0)
                return -1;
        }
        else if (strcmp(opt, "--duration-s") == 0)
        {
            if (parse_u32(val, &args->duration_s) != 0)
                return -1;
        }
        else if (strcmp(opt, "--trim-s") == 0)
        {
            if (parse_u32(val, &args->trim_s) != 0)
                return -1;
        }
        else if (strcmp(opt, "--path") == 0)
        {
            args->path = val;
        }
        else if (strcmp(opt, "--local-ip") == 0)
        {
            args->local_ip = val;
        }
        else if (strcmp(opt, "--remote-ip") == 0)
        {
            args->remote_ip = val;
        }
        else if (strcmp(opt, "--output") == 0)
        {
            args->output = val;
        }
        else if (strcmp(opt, "--local-port") == 0)
        {
            uint32_t p;
            if (parse_u32(val, &p) != 0 || p > 65535)
                return -1;
            args->local_port = (uint16_t)p;
        }
        else if (strcmp(opt, "--remote-port") == 0)
        {
            uint32_t p;
            if (parse_u32(val, &p) != 0 || p > 65535)
                return -1;
            args->remote_port = (uint16_t)p;
        }
        else if (strcmp(opt, "--teid") == 0)
        {
            if (parse_u32(val, &args->teid) != 0 || args->teid == 0)
                return -1;
        }
        else if (strcmp(opt, "--service-id") == 0)
        {
            if (parse_int(val, &args->service_id) != 0)
                return -1;
        }
        else if (strcmp(opt, "--main-lcore") == 0)
        {
            if (parse_int(val, &args->main_lcore) != 0)
                return -1;
        }
        else if (strcmp(opt, "--bind-core") == 0)
        {
            if (parse_int(val, &args->bind_core) != 0)
                return -1;
        }
        else if (strcmp(opt, "--rtt-rx-core") == 0)
        {
            if (parse_int(val, &args->rtt_rx_core) != 0)
                return -1;
        }
        else
        {
            fprintf(stderr, "unknown option: %s\n", opt);
            usage(argv[0]);
            return -1;
        }
        ++i;
    }

    if ((int)args->mode == -1)
    {
        fprintf(stderr, "missing --mode\n");
        usage(argv[0]);
        return -1;
    }

    if (args->path == NULL)
        args->path = "ldp";
    if (strcmp(args->path, "cross") != 0 && strcmp(args->path, "ldp") != 0)
    {
        fprintf(stderr, "invalid path: %s\n", args->path);
        return -1;
    }

    const bool is_tx = (args->mode == MODE_TX_PPS || args->mode == MODE_TX_RTT);
    const bool is_ldp = (strcmp(args->path, "ldp") == 0);
    if (args->local_ip == NULL)
        args->local_ip = is_ldp ? (is_tx ? LDP_TX_IP : LDP_RX_IP)
                                : (is_tx ? CROSS_TX_IP : CROSS_RX_IP);
    if (args->remote_ip == NULL)
        args->remote_ip = is_ldp ? (is_tx ? LDP_RX_IP : LDP_TX_IP)
                                 : (is_tx ? CROSS_RX_IP : CROSS_TX_IP);

    if (args->service_id < 0)
        args->service_id = is_tx ? 502 : 501;
    if (args->main_lcore < 0)
        args->main_lcore = is_tx ? 24 : 22;
    if (args->bind_core < 0)
        args->bind_core = is_tx ? 25 : 23;
    if (args->rtt_rx_core < 0 && args->mode == MODE_TX_RTT)
        args->rtt_rx_core = 26;

    if (args->bind_core == args->main_lcore)
    {
        fprintf(stderr, "bind-core must differ from main-lcore\n");
        return -1;
    }
    if (args->mode == MODE_TX_RTT && args->rtt_rx_core == args->bind_core)
    {
        fprintf(stderr, "rtt-rx-core must differ from bind-core\n");
        return -1;
    }
    if ((args->mode == MODE_TX_RTT) && args->payload_bytes < sizeof(pkt_hdr_t))
    {
        fprintf(stderr, "payload-bytes must be >= %zu for tx-rtt mode\n", sizeof(pkt_hdr_t));
        return -1;
    }
    return 0;
}

/* ── fnp_init ────────────────────────────────────────────────────────── */
static int init_fnp(const demo_args_t *args)
{
    int lcores[2] = {args->bind_core, args->rtt_rx_core};
    fnp_init_conf_t conf = {0};
    conf.main_lcore = args->main_lcore;
    conf.lcores = lcores;
    conf.num_lcores = (args->mode == MODE_TX_RTT) ? 2 : 1;
    conf.id = (uint16_t)args->service_id;
    snprintf(conf.name, sizeof(conf.name), "node-perf");
    return fnp_init(&conf);
}

/* ── main ────────────────────────────────────────────────────────────── */
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

    if (args.mode == MODE_TX_RTT)
    {
        /* ── two-lcore path: TX lcore sends, RX lcore records RTT ── */
        rtt_shared_t sh = {
            .args = &args,
            .socket = NULL,
            .socket_ready = ATOMIC_VAR_INIT(false),
            .tx_ok = 0,
            .tx_done = ATOMIC_VAR_INIT(false),
            .rx_done = ATOMIC_VAR_INIT(false),
        };
        lcore_job_t rx_job = {.ctx = &sh, .done = ATOMIC_VAR_INIT(false), .ret = 0};
        lcore_job_t tx_job = {.ctx = &sh, .done = ATOMIC_VAR_INIT(false), .ret = 0};

        /* start RX lcore first so it is ready before TX begins sending */
        ret = fnp_lcore_launch((unsigned)args.rtt_rx_core, rtt_rx_lcore, &rx_job);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "fnp_lcore_launch rx failed: %d\n", ret);
            return 1;
        }

        ret = fnp_lcore_launch((unsigned)args.bind_core, rtt_tx_lcore, &tx_job);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "fnp_lcore_launch tx failed: %d\n", ret);
            return 1;
        }

        while (!atomic_load_explicit(&rx_job.done, memory_order_acquire) ||
               !atomic_load_explicit(&tx_job.done, memory_order_acquire))
        {
            struct timespec ts = {0, 100000000L};
            nanosleep(&ts, NULL);
        }
        fnp_lcore_wait((unsigned)args.bind_core);
        fnp_lcore_wait((unsigned)args.rtt_rx_core);
        if (sh.socket)
            fnp_socket_close(sh.socket);
        return (tx_job.ret != 0 || rx_job.ret != 0) ? 1 : 0;
    }

    /* ── single-lcore path ── */
    lcore_job_t job = {.ctx = &args, .done = ATOMIC_VAR_INIT(false), .ret = 0};
    ret = fnp_lcore_launch((unsigned)args.bind_core, single_lcore_func, &job);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_lcore_launch failed: %d\n", ret);
        return 1;
    }

    while (!atomic_load_explicit(&job.done, memory_order_acquire))
    {
        struct timespec ts = {0, 100000000L};
        nanosleep(&ts, NULL);
    }
    fnp_lcore_wait((unsigned)args.bind_core);
    return job.ret;
}
