#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  scripts/install-fnp.sh [--prefix DIR] [--build-dir DIR] [--headers-dir DIR]

Options:
  --prefix DIR       Install prefix. Default: /opt/fnp
  --build-dir DIR    Directory containing built libraries. Default: <repo>/build
  --headers-dir DIR  Directory containing public headers. Default: <repo>/inc
  -h, --help         Show this help message

Examples:
  scripts/install-fnp.sh
  scripts/install-fnp.sh --prefix /usr/local/fnp
  scripts/install-fnp.sh --prefix /tmp/fnp-sdk --build-dir /root/fnp/build
EOF
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd)

PREFIX="${FNP_INSTALL_PREFIX:-/opt/fnp}"
BUILD_DIR="${REPO_ROOT}/build"
HEADERS_DIR="${REPO_ROOT}/inc"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            [[ $# -ge 2 ]] || { echo "missing value for --prefix" >&2; exit 1; }
            PREFIX="$2"
            shift 2
            ;;
        --build-dir)
            [[ $# -ge 2 ]] || { echo "missing value for --build-dir" >&2; exit 1; }
            BUILD_DIR="$2"
            shift 2
            ;;
        --headers-dir)
            [[ $# -ge 2 ]] || { echo "missing value for --headers-dir" >&2; exit 1; }
            HEADERS_DIR="$2"
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

if [[ ! -d "${HEADERS_DIR}" ]]; then
    echo "headers directory not found: ${HEADERS_DIR}" >&2
    exit 1
fi

if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "build directory not found: ${BUILD_DIR}" >&2
    exit 1
fi

mapfile -t HEADER_FILES < <(find "${HEADERS_DIR}" -maxdepth 1 -type f -name '*.h' | sort)

if [[ ${#HEADER_FILES[@]} -eq 0 ]]; then
    echo "no header files found in: ${HEADERS_DIR}" >&2
    exit 1
fi

LIB_FILES=(
    "${BUILD_DIR}/libfnp-api.so"
    "${BUILD_DIR}/libfnp-api.a"
)

for lib in "${LIB_FILES[@]}"; do
    if [[ ! -f "${lib}" ]]; then
        echo "required library not found: ${lib}" >&2
        echo "please build fnp first, for example: cmake -S . -B build && cmake --build build -j" >&2
        exit 1
    fi
done

INSTALL_INCLUDE_DIR="${PREFIX}/include"
INSTALL_LIB_DIR="${PREFIX}/lib"

install -d "${INSTALL_INCLUDE_DIR}" "${INSTALL_LIB_DIR}"

for header in "${HEADER_FILES[@]}"; do
    install -m 0644 "${header}" "${INSTALL_INCLUDE_DIR}/"
done

for lib in "${LIB_FILES[@]}"; do
    install -m 0644 "${lib}" "${INSTALL_LIB_DIR}/"
done

echo "installed FNP headers to: ${INSTALL_INCLUDE_DIR}"
echo "installed FNP libraries to: ${INSTALL_LIB_DIR}"
echo
echo "note: fnp public headers still include DPDK headers, so consumers may still need a DPDK include path when compiling."
