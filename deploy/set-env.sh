#!/bin/bash
set -e

cd /opt/dpdk/bin/
modprobe uio_pci_generic

ip link set ens224 down
./dpdk-devbind.py -b=uio_pci_generic ens224

./dpdk-hugepages.py -p 1G --setup 4G
./dpdk-hugepages.py -s