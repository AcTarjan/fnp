#!/bin/bash
set -e

cd /opt/dpdk/bin/
#modprobe uio_pci_generic
modprobe vfio-pci
# 适用于不支持iommu的设备
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

#ethtool -K ens160 gso off
#ethtool -K ens160 lro off

ip link set ens160 down
./dpdk-devbind.py -b=vfio-pci ens160

./dpdk-hugepages.py -p 1G --setup 4G
./dpdk-hugepages.py -s

# 查看网卡队列中断号：cat /proc/interrupts | grep ens256
