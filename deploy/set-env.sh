set -e

cd /opt/dpdk/bin/
modprobe uio_pci_generic
./dpdk-devbind.py -b=uio_pci_generic ens160

./dpdk-hugepages.py -p 1G --setup 4G
./dpdk-hugepages.py -s