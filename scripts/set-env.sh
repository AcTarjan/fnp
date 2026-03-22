#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DPDK_DIR="/opt/dpdk"

cd "${DPDK_DIR}/bin"
modprobe vfio-pci
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

ip link set ens160 down
./dpdk-devbind.py -b=vfio-pci ens160

./dpdk-hugepages.py -p 1G --setup 4G
./dpdk-hugepages.py -s
