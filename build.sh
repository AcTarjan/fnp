#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./build.sh [--build-dir DIR] [--dpdk-dir DIR] [--build-type TYPE] [--daemon-dpdk-link MODE]

Options:
  --build-dir DIR    CMake build directory. Default: ./build
  --dpdk-dir DIR     DPDK install prefix. Default: /opt/dpdk
  --build-type TYPE  CMake build type. Default: Release
  --daemon-dpdk-link MODE
                    fnp-daemon DPDK link mode: static or dynamic. Default: static
  -h, --help         Show this help message
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT="${SCRIPT_DIR}"

BUILD_DIR="${REPO_ROOT}/build"
DPDK_DIR="${DPDK_DIR:-/opt/dpdk}"
BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
DAEMON_DPDK_LINK_MODE="${FNP_DAEMON_DPDK_LINK_MODE:-static}"
OUTPUT_BIN="${REPO_ROOT}/k8s/fnp-daemon"
OUTPUT_LIB_DIR="${REPO_ROOT}/lib"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir)
            [[ $# -ge 2 ]] || { echo "missing value for --build-dir" >&2; exit 1; }
            BUILD_DIR="$2"
            shift 2
            ;;
        --dpdk-dir)
            [[ $# -ge 2 ]] || { echo "missing value for --dpdk-dir" >&2; exit 1; }
            DPDK_DIR="$2"
            shift 2
            ;;
        --build-type)
            [[ $# -ge 2 ]] || { echo "missing value for --build-type" >&2; exit 1; }
            BUILD_TYPE="$2"
            shift 2
            ;;
        --daemon-dpdk-link)
            [[ $# -ge 2 ]] || { echo "missing value for --daemon-dpdk-link" >&2; exit 1; }
            DAEMON_DPDK_LINK_MODE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "${DAEMON_DPDK_LINK_MODE}" in
    static)
        FNP_DAEMON_STATIC_DPDK=ON
        ;;
    dynamic)
        FNP_DAEMON_STATIC_DPDK=OFF
        ;;
    *)
        echo "invalid --daemon-dpdk-link value: ${DAEMON_DPDK_LINK_MODE}" >&2
        echo "expected: static or dynamic" >&2
        exit 1
        ;;
esac

cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
    -DDPDK_DIR="${DPDK_DIR}" \
    -DFNP_DAEMON_STATIC_DPDK="${FNP_DAEMON_STATIC_DPDK}"
cmake --build "${BUILD_DIR}" -j"$(nproc)"

install -d "${OUTPUT_LIB_DIR}" "${REPO_ROOT}/k8s"
install -m 0755 "${BUILD_DIR}/fnp-daemon" "${OUTPUT_BIN}"
install -m 0644 "${BUILD_DIR}/libfnp-api.so" "${OUTPUT_LIB_DIR}/libfnp-api.so"
install -m 0644 "${BUILD_DIR}/libfnp-api.a" "${OUTPUT_LIB_DIR}/libfnp-api.a"

echo "built fnp-daemon: ${OUTPUT_BIN}"
echo "fnp-daemon DPDK link mode: ${DAEMON_DPDK_LINK_MODE}"
echo "built fnp libraries:"
echo "  ${OUTPUT_LIB_DIR}/libfnp-api.so"
echo "  ${OUTPUT_LIB_DIR}/libfnp-api.a"
