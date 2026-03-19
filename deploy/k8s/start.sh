#!/usr/bin/env bash
set -euo pipefail

DPDK_DIR="/opt/dpdk"
for candidate in \
    "${DPDK_DIR}/lib/$(uname -m)-linux-gnu" \
    "${DPDK_DIR}/lib64" \
    "${DPDK_DIR}/lib"
do
    if [ -d "${candidate}" ]; then
        export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:${candidate}"
    fi
done
# libnuma.so.1: cannot open shared object file: No such file or directory
#yum install numactl-devel

# Cannot open '/var/run/dpdk/master/config' for rte_mem_config
# mount /var/run/dpdk/

./dpdkSlaveApp &

tail -f /dev/null
