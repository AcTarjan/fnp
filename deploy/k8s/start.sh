#!/bin/bash

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/dpdk/lib64/
# libnuma.so.1: cannot open shared object file: No such file or directory
#yum install numactl-devel

# Cannot open '/var/run/dpdk/master/config' for rte_mem_config
# mount /var/run/dpdk/

./dpdkSlaveApp &

tail -f /dev/null