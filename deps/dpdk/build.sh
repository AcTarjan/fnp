#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR="${SCRIPT_DIR}/dpdk-stable-22.11.8"
BUILD_DIR="${SRC_DIR}/build"
INSTALL_PREFIX="${DPDK_INSTALL_PREFIX:-/opt/dpdk}"
LD_CONF_FILE="${DPDK_LD_CONF_FILE:-/etc/ld.so.conf.d/dpdk.conf}"

resolve_dpdk_lib_dir() {
    local prefix="$1"
    for candidate in \
        "${prefix}/lib/$(uname -m)-linux-gnu" \
        "${prefix}/lib64" \
        "${prefix}/lib"
    do
        if [ -d "${candidate}" ]; then
            printf '%s\n' "${candidate}"
            return 0
        fi
    done

    return 1
}

if [ "$(id -u)" -ne 0 ]; then
    echo "please run this script as root, for example: sudo bash deps/dpdk/build.sh"
    exit 1
fi

echo "current dir: ${SCRIPT_DIR}"
echo "start build dpdk..."
echo "install prefix: ${INSTALL_PREFIX}"

if [ ! -d "${SRC_DIR}" ]; then
    tar -xf "${SCRIPT_DIR}/dpdk-22.11.8.tar.xz" -C "${SCRIPT_DIR}"
fi

cd "${SRC_DIR}"

# 安装pyelftools依赖
python -m venv venv
source venv/bin/activate
pip install --upgrade pip 
pip install pyelftools

if [ -d "${BUILD_DIR}" ]; then
    meson setup --prefix="${INSTALL_PREFIX}" --reconfigure "${BUILD_DIR}"
else
    meson setup --prefix="${INSTALL_PREFIX}" "${BUILD_DIR}"
fi

ninja -C "${BUILD_DIR}" -j"$(nproc)"
ninja -C "${BUILD_DIR}" install

DPDK_LIB_DIR="$(resolve_dpdk_lib_dir "${INSTALL_PREFIX}")"
printf '%s\n' "${DPDK_LIB_DIR}" > "${LD_CONF_FILE}"
ldconfig

echo "build dpdk successfully"
echo "dpdk libraries registered in ${LD_CONF_FILE}: ${DPDK_LIB_DIR}"
