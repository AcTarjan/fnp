#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  deploy/set-tap.sh start [tap_name] [kernel_ip/cidr]
  deploy/set-tap.sh stop [tap_name]
  deploy/set-tap.sh delete [tap_name]
  deploy/set-tap.sh show [tap_name]

Examples:
  sudo deploy/set-tap.sh start fnp-tap0 192.168.66.66/24
  sudo deploy/set-tap.sh show fnp-tap0
EOF
}

wait_for_tap() {
    local tap_name="$1"
    local timeout_secs="$2"
    local deadline=$((SECONDS + timeout_secs))

    while (( SECONDS <= deadline )); do
        if ip link show dev "${tap_name}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done

    return 1
}

if [[ "$(id -u)" -ne 0 ]]; then
    echo "please run as root" >&2
    exit 1
fi

ACTION="${1:-start}"
TAP_NAME="${2:-fnp-tap0}"
KERNEL_ADDR="${3:-192.168.66.66/24}"
WAIT_SECS="${FNP_TAP_WAIT_SECS:-15}"
MTU="${FNP_TAP_MTU:-1500}"

case "${ACTION}" in
    start|up)
        if ! wait_for_tap "${TAP_NAME}" "${WAIT_SECS}"; then
            echo "tap device ${TAP_NAME} not found. Start fnp-daemon with conf/fnp-tap.yaml first." >&2
            exit 1
        fi

        ip link set dev "${TAP_NAME}" mtu "${MTU}"
        ip link set dev "${TAP_NAME}" up
        ip -4 addr flush dev "${TAP_NAME}"
        ip addr add "${KERNEL_ADDR}" dev "${TAP_NAME}"

        echo "kernel side tap is ready:"
        ip -br addr show dev "${TAP_NAME}"
        ;;
    stop|down)
        if ip link show dev "${TAP_NAME}" >/dev/null 2>&1; then
            ip -4 addr flush dev "${TAP_NAME}" || true
            ip link set dev "${TAP_NAME}" down
        fi
        ;;
    delete)
        if ip link show dev "${TAP_NAME}" >/dev/null 2>&1; then
            ip link del dev "${TAP_NAME}"
        fi
        ;;
    show)
        ip -details addr show dev "${TAP_NAME}"
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
