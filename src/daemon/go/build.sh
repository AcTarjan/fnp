#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "${SCRIPT_DIR}"

# 先补全 go.sum，避免首次构建直接失败。
go mod download

# c-archive 会生成 libfnp-conf.a 和对应的 libfnp-conf.h。
# 先在临时目录里生成，避免复用当前目录里上次残留的头文件内容。
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "${BUILD_DIR}"' EXIT

go build -buildmode=c-archive -o "${BUILD_DIR}/libfnp-conf.a" main.go
cp "${BUILD_DIR}/libfnp-conf.a" ./libfnp-conf.a
cp "${BUILD_DIR}/libfnp-conf.h" ./libfnp-conf.h

# 某些 Go 版本生成的头文件没有 include guard，这里只在缺失时补一层，
# 避免再次包装导致整份头文件被二次屏蔽。
if ! grep -q '^#ifndef LIBFNP_CONF_H$' ./libfnp-conf.h; then
    TMP_HEADER=$(mktemp)
    {
        echo "#ifndef LIBFNP_CONF_H"
        echo "#define LIBFNP_CONF_H"
        cat ./libfnp-conf.h
        echo
        echo "#endif /* LIBFNP_CONF_H */"
    } > "${TMP_HEADER}"
    mv "${TMP_HEADER}" ./libfnp-conf.h
fi
