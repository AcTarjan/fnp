#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "${SCRIPT_DIR}"

# 先补全 go.sum，避免首次构建直接失败。
go mod download

# c-archive 会生成 libfnp-conf.a 和对应的 libfnp-conf.h。
go build -buildmode=c-archive -o ./libfnp-conf.a main.go

# Go 生成的头文件没有 include guard，这里补一层，避免被多次包含时类型重定义。
TMP_HEADER=$(mktemp)
{
    echo "#ifndef LIBFNP_CONF_H"
    echo "#define LIBFNP_CONF_H"
    cat ./libfnp-conf.h
    echo
    echo "#endif /* LIBFNP_CONF_H */"
} > "${TMP_HEADER}"
mv "${TMP_HEADER}" ./libfnp-conf.h
