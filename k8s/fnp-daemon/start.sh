#!/usr/bin/env bash
set -euo pipefail

FNP_ROOT="${FNP_ROOT:-/root/fnp}"
FNP_LOG_DIR="${FNP_LOG_DIR:-${FNP_ROOT}}"
FNP_LOG_FILE="${FNP_LOG_FILE:-${FNP_LOG_DIR}/fnp-daemon.log}"
FNP_BIN="${FNP_BIN:-/root/fnp-daemon}"
FNP_CONFIG="${FNP_CONFIG:-/root/fnp.yaml}"

mkdir -p /var/run/dpdk
mkdir -p "${FNP_ROOT}"
mkdir -p "${FNP_LOG_DIR}"
touch "${FNP_LOG_FILE}"

if [[ ! -x "${FNP_BIN}" ]]; then
    echo "fnp-daemon binary not found: ${FNP_BIN}" >&2
    exit 1
fi

echo "starting fnp-daemon: ${FNP_BIN} ${FNP_CONFIG}"
echo "log file: ${FNP_LOG_FILE}"
echo "host /var/run/fnp is mounted to ${FNP_ROOT}"
echo "image binary: /root/fnp-daemon"
echo "image configs: /root/fnp.yaml /root/fnp-tap.yaml"

"${FNP_BIN}" "${FNP_CONFIG}" >>"${FNP_LOG_FILE}" 2>&1 &
DAEMON_PID=$!

echo "fnp-daemon pid: ${DAEMON_PID}"
exec sleep infinity
