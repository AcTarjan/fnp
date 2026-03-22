#!/usr/bin/env bash
set -euo pipefail

# 编译fnp的多阶段基础镜像：
# 1. fnp-build:v1  用于构建DPDK和fnp
# 2. fnp-base:v1   仅保留运行fnp-daemon所需的DPDK运行时和基础工具

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${SCRIPT_DIR}/../.." && pwd)

docker build \
  -f "${REPO_ROOT}/k8s/baseimage/Dockerfile" \
  --target fnp-build \
  -t fnp-build:v1 \
  "${REPO_ROOT}"

docker build \
  -f "${REPO_ROOT}/k8s/baseimage/Dockerfile" \
  --target fnp-base \
  -t fnp-base:v1 \
  "${REPO_ROOT}"
