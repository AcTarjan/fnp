#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR="${SCRIPT_DIR}/dpdk-stable-22.11.8"
BUILD_DIR="${SRC_DIR}/build"

echo "current dir: ${SCRIPT_DIR}"
echo "start build dpdk..."

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
    meson setup --prefix="${SCRIPT_DIR}" --reconfigure "${BUILD_DIR}"
else
    meson setup --prefix="${SCRIPT_DIR}" "${BUILD_DIR}"
fi

ninja -C "${BUILD_DIR}" -j"$(nproc)"
ninja -C "${BUILD_DIR}" install

echo "build dpdk successfully"
