cmake_minimum_required(VERSION 3.17)
project(fnps C)

set(CMAKE_C_STANDARD 11)

# import dpdk
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")
include_directories(/opt/dpdk-23.11/include)
link_directories(/opt/dpdk-23.11/lib64)

include_directories(src/inc)
include_directories(src/common)

add_library(fnps SHARED
        src/common/fnp_hash.c
        src/common/fnp_ring.c
        src/fnps.c
        src/tcp/fnp_tcp_sock.c
        src/tcp/fnp_tcp_in.c
        src/tcp/fnp_tcp_out.c
        src/fnp_init.c
        src/fnp_ipv4.c
        src/fnp_icmp.c
        src/fnp_arp.c
        src/fnp_ether.c
        src/fnp_worker.c
        src/tcp/fnp_tcp.c
        src/tcp/fnp_tcp_timer.c
        src/tcp/fnp_tcp_ofo.c
)

target_compile_definitions(fnps PRIVATE USE_DPDK)

add_executable(test test/main.c)

add_executable(test_hash test/test_hash.c src/common/fnp_hash.c)

add_executable(test_ring test/test_ring.c src/common/fnp_ring.c)
target_link_libraries(test_ring pthread)

target_link_libraries(test fnps
        rte_hash rte_ip_frag rte_timer
        rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal
        rte_kvargs rte_telemetry rte_net rte_meter
        pthread
)