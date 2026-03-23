#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR="${SCRIPT_DIR}/dpdk-stable-22.11.8"
BUILD_DIR="${SRC_DIR}/build"
VENV_DIR="${SRC_DIR}/venv"
DPDK_TARBALL="${SCRIPT_DIR}/dpdk-22.11.8.tar.xz"
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

if [ ! -f "${DPDK_TARBALL}" ]; then
    echo "missing DPDK tarball: ${DPDK_TARBALL}"
    exit 1
fi

if [ ! -d "${SRC_DIR}" ]; then
    tar -xf "${DPDK_TARBALL}" -C "${SCRIPT_DIR}"
fi

cd "${SRC_DIR}"

# 用独立 venv 安装 meson/ninja/pyelftools，避免依赖宿主机 python 环境。
rm -rf "${VENV_DIR}"
rm -rf "${BUILD_DIR}"
python3 -m venv "${VENV_DIR}"

if [ -x "${VENV_DIR}/bin/python3" ]; then
    VENV_PYTHON="${VENV_DIR}/bin/python3"
else
    VENV_PYTHON="${VENV_DIR}/bin/python"
fi
export PATH="${VENV_DIR}/bin:${PATH}"

"${VENV_PYTHON}" -m pip install --upgrade pip
"${VENV_PYTHON}" -m pip install pyelftools meson ninja

meson setup --prefix="${INSTALL_PREFIX}" "${BUILD_DIR}"

ninja -C "${BUILD_DIR}" -j"$(nproc)"
ninja -C "${BUILD_DIR}" install

DPDK_LIB_DIR="$(resolve_dpdk_lib_dir "${INSTALL_PREFIX}")"
printf '%s\n' "${DPDK_LIB_DIR}" > "${LD_CONF_FILE}"
ldconfig

echo "build dpdk successfully"
echo "dpdk libraries registered in ${LD_CONF_FILE}: ${DPDK_LIB_DIR}"
