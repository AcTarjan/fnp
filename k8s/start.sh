#!/usr/bin/env bash
set -euo pipefail

FNP_CONFIG="${FNP_CONFIG:-/root/fnp.yaml}"
FNP_LOG_FILE="${FNP_LOG_FILE:-/root/fnp-daemon.log}"
FNP_BIN="${FNP_BIN:-/root/fnp-daemon}"

if [[ ! -x "${FNP_BIN}" ]]; then
    echo "fnp-daemon binary not found: ${FNP_BIN}" >&2
    exit 1
fi

touch "${FNP_LOG_FILE}"

"${FNP_BIN}" "${FNP_CONFIG}" >>"${FNP_LOG_FILE}" 2>&1 &

exec tail -F "${FNP_LOG_FILE}"
