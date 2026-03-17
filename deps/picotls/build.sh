#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SRC_DIR="${SCRIPT_DIR}/picotls-src"
BUILD_DIR="${SRC_DIR}/build"

if [ ! -d "${SRC_DIR}" ]; then
    tar -xf "${SCRIPT_DIR}/picotls-src.tgz" -C "${SCRIPT_DIR}"
fi

cmake -S "${SRC_DIR}" -B "${BUILD_DIR}"
cmake --build "${BUILD_DIR}" -j"$(nproc)"

# 回到源码目录收集构建产物。
cd "${SRC_DIR}"
# 复制头文件到 include 目录，供后续编译使用。
mkdir -p "${SCRIPT_DIR}/include"
cp -r ./include/. "${SCRIPT_DIR}/include/"

# 安装到当前目录下的 lib 目录，供后续链接使用。
mkdir -p "${SCRIPT_DIR}/lib"
cp -f "${BUILD_DIR}"/libpicotls-* "${SCRIPT_DIR}/lib/"
