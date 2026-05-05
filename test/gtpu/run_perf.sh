#!/usr/bin/env bash
# run_perf.sh - FNP pps/rtt test launcher (runs inside container)
#
# Two path modes:
#
#   --path ldp   (default) Same-node LDP test, server 231 only.
#                Starts daemon + RX + TX all in one container.
#
#   --path cross Cross-node test over physical link (229 <-> 231).
#                Requires --role rx or --role tx.
#                  --role rx : start daemon + RX app on server 231, wait forever
#                  --role tx : start daemon + TX app on server 229, exit when done
#
# Parameters:
#   --mode pps|rtt      test type
#   --path ldp|cross    data path, default ldp
#   --role tx|rx        required when --path cross
#   --payload-bytes N   packet payload size (bytes), default 256
#   --kpps N            offered rate (kpps), default 10
#   --duration-s N      TX send window (seconds), default 30
#   --trim-s N          RTT head/tail trim seconds, default 5
#
# Lcore layout:
#   LDP (server 231):
#     Daemon  : main=20  worker=21
#     RX app  : main=22  bind=23
#     TX app  : main=24  bind=25  [rtt-rx=26]
#   Cross RX (server 231):
#     Daemon  : main=20  worker=21
#     RX app  : main=22  bind=23
#   Cross TX (server 229):
#     Daemon  : main=20  worker=21
#     TX app  : main=22  bind=23  [rtt-rx=24]
#
# Usage examples (run inside container):
#   ./run_perf.sh --mode pps --kpps 500 --payload-bytes 256 --duration-s 20
#   ./run_perf.sh --mode rtt --kpps 10  --payload-bytes 256 --duration-s 30
#   ./run_perf.sh --path cross --role rx --mode pps
#   ./run_perf.sh --path cross --role tx --mode rtt --kpps 50 --duration-s 60

set -euo pipefail

MODE="rtt"
PATH_MODE="ldp"
ROLE=""
PAYLOAD=256
KPPS=10
DURATION=30
TRIM_S=5

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)          MODE="$2";      shift 2 ;;
        --path)          PATH_MODE="$2"; shift 2 ;;
        --role)          ROLE="$2";      shift 2 ;;
        --payload-bytes) PAYLOAD="$2";   shift 2 ;;
        --kpps)          KPPS="$2";      shift 2 ;;
        --duration-s)    DURATION="$2";  shift 2 ;;
        --trim-s)        TRIM_S="$2";    shift 2 ;;
        *) echo "unknown argument: $1"; exit 1 ;;
    esac
done

[[ "$MODE" == "pps" || "$MODE" == "rtt" ]] || { echo "ERROR: --mode must be pps or rtt"; exit 1; }
[[ "$PATH_MODE" == "ldp" || "$PATH_MODE" == "cross" ]] || { echo "ERROR: --path must be ldp or cross"; exit 1; }
if [[ "$PATH_MODE" == "cross" ]]; then
    [[ "$ROLE" == "tx" || "$ROLE" == "rx" ]] || { echo "ERROR: --path cross requires --role tx or rx"; exit 1; }
fi

DEMO=/root/fnp-node-perf-demo
DAEMON=/root/fnp-daemon
RTT_OUT="/tmp/rtt_$(date +%Y%m%d_%H%M%S).csv"
ANALYZE=/root/analyze_rtt.py

# Select daemon config based on path/role
if [[ "$PATH_MODE" == "ldp" ]]; then
    CONF=/root/conf/fnp-ldp.yaml
elif [[ "$ROLE" == "rx" ]]; then
    CONF=/root/conf/fnp-cross-rx.yaml
else
    CONF=/root/conf/fnp-cross-tx.yaml
fi

echo "================================================================"
echo " FNP ${PATH_MODE^^} ${MODE} test${ROLE:+  role=${ROLE}}"
echo "   kpps=${KPPS}  payload=${PAYLOAD}B  duration=${DURATION}s  trim=${TRIM_S}s"
echo "   conf=${CONF}"
echo "================================================================"

# ── cleanup on exit ───────────────────────────────────────────────────
RX_PID=""
DAEMON_PID=""
cleanup() {
    [[ -n "$RX_PID" ]]     && kill "$RX_PID"     2>/dev/null || true
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID"  2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf /var/run/dpdk/fnp          2>/dev/null || true
    rm -f  /dev/hugepages/fnpmap_*    2>/dev/null || true
}
trap cleanup EXIT

# ── start daemon ──────────────────────────────────────────────────────
echo "[daemon] starting..."
rm -rf /var/run/dpdk/fnp
rm -f  /dev/hugepages/fnpmap_* 2>/dev/null || true
"$DAEMON" "$CONF" &
DAEMON_PID=$!

echo -n "[daemon] waiting for ready"
for i in $(seq 1 60); do
    if [[ -S /var/run/dpdk/fnp/mp_socket && -f /var/run/dpdk/fnp/ready ]]; then
        echo "  OK (${i}s)"
        break
    fi
    sleep 1
    echo -n "."
done
if [[ ! -S /var/run/dpdk/fnp/mp_socket ]]; then
    echo ""
    echo "[daemon] ERROR: failed to start"
    exit 1
fi

# ── start RX app in background ────────────────────────────────────────
if [[ "$MODE" == "pps" ]]; then
    RX_MODE="rx-pps"
else
    RX_MODE="rx-rtt"
fi

# Determine whether we need to start RX here
# LDP: always start RX; cross rx: start RX; cross tx: skip
START_RX=true
if [[ "$PATH_MODE" == "cross" && "$ROLE" == "tx" ]]; then
    START_RX=false
fi

if [[ "$START_RX" == "true" ]]; then
    echo "[rx] starting ${RX_MODE} (service-id=501 main-lcore=22 bind-core=23)..."
    "$DEMO" \
        --mode "$RX_MODE" --path "$PATH_MODE" \
        --payload-bytes "$PAYLOAD" \
        --service-id 501 --main-lcore 22 --bind-core 23 &
    RX_PID=$!
    sleep 1  # give frontend time to register with daemon
fi

# Cross RX role: wait indefinitely (kill container to stop)
if [[ "$PATH_MODE" == "cross" && "$ROLE" == "rx" ]]; then
    echo "[rx] cross-node RX ready – waiting for TX on remote node (Ctrl-C to stop)"
    wait "$RX_PID"
    exit 0
fi

# ── run TX ────────────────────────────────────────────────────────────
# Lcore assignment depends on path:
#   LDP   : TX main=24 bind=25 rtt-rx=26
#   cross : TX main=22 bind=23 rtt-rx=24
if [[ "$PATH_MODE" == "ldp" ]]; then
    TX_MAIN=24; TX_BIND=25; TX_RTTRC=26
else
    TX_MAIN=22; TX_BIND=23; TX_RTTRC=24
fi

if [[ "$MODE" == "pps" ]]; then
    echo "[tx] starting tx-pps (main-lcore=${TX_MAIN} bind-core=${TX_BIND})..."
    "$DEMO" \
        --mode tx-pps --path "$PATH_MODE" \
        --kpps "$KPPS" --payload-bytes "$PAYLOAD" --duration-s "$DURATION" \
        --service-id 502 --main-lcore "$TX_MAIN" --bind-core "$TX_BIND"
else
    echo "[tx] starting tx-rtt (main-lcore=${TX_MAIN} bind-core=${TX_BIND} rtt-rx-core=${TX_RTTRC})..."
    "$DEMO" \
        --mode tx-rtt --path "$PATH_MODE" \
        --kpps "$KPPS" --payload-bytes "$PAYLOAD" --duration-s "$DURATION" \
        --output "$RTT_OUT" \
        --service-id 502 --main-lcore "$TX_MAIN" --bind-core "$TX_BIND" --rtt-rx-core "$TX_RTTRC"
fi

# ── stop RX (LDP only; cross-tx has no local RX) ─────────────────────
if [[ -n "$RX_PID" ]]; then
    echo "[rx] stopping ${RX_MODE}..."
    kill "$RX_PID" 2>/dev/null || true
    wait "$RX_PID" 2>/dev/null || true
    RX_PID=""
fi

# ── RTT post-processing ───────────────────────────────────────────────
if [[ "$MODE" == "rtt" ]]; then
    if [[ -f "$RTT_OUT" ]]; then
        echo ""
        echo "================================================================"
        echo " RTT Analysis  (trim head+tail ${TRIM_S}s × ${KPPS} kpps)"
        echo "================================================================"
        python3 "$ANALYZE" "$RTT_OUT" "$KPPS" "$TRIM_S"
        echo "RTT CSV saved: $RTT_OUT"
    else
        echo "WARNING: RTT output file not found: $RTT_OUT"
    fi
fi

echo "================================================================"
echo " done"
echo "================================================================"
