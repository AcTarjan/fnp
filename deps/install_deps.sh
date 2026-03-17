#!/usr/bin/env bash
set -euo pipefail

echo "start install system dependencies for fnp..."

apt update

# pciutils: dpdk-devbind.py 依赖查询 PCI 设备信息
# libnuma-dev: dpdk 依赖 NUMA 库
# libpcap-dev: dpdk 的 pcapdump 依赖 libpcap 库进行网络数据包捕获和分析

apt install -y \
    libnuma-dev \
    libpcap-dev \
    pciutils