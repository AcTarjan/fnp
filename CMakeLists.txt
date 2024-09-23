cmake_minimum_required(VERSION 3.17)
project(fnp C)

set(CMAKE_C_STANDARD 11)

# import dpdk
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")
include_directories(/opt/dpdk/include)
link_directories(/opt/dpdk/lib64)

include_directories(src/inc)
include_directories(src/tcp/inc)
include_directories(src/common)

add_library(fnp SHARED
        src/common/fnp_hash.c
        src/common/fnp_ring.c
        src/tcp/fnp_tcp_timer.c
        src/tcp/fnp_tcp_ofo.c
        src/tcp/fnp_tcp_sock.c
        src/tcp/fnp_tcp_in.c
        src/tcp/fnp_tcp_out.c
        src/fnp_init.c
        src/fnp_ipv4.c
        src/fnp_icmp.c
        src/fnp_arp.c
        src/fnp_ether.c
        src/fnp_worker.c
        src/common/fnp_pring.c
)

target_compile_definitions(fnp PRIVATE USE_DPDK)

add_executable(tcp_server examples/fnp_tcp_server.c)
add_executable(send_tcp examples/send_tcp.c)

add_executable(test_hash examples/test_hash.c src/common/fnp_hash.c)

add_executable(test_ring examples/test_ring.c src/common/fnp_ring.c)
target_link_libraries(test_ring pthread)

target_link_libraries(tcp_server fnp
        rte_hash rte_ip_frag rte_timer
        rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal
        rte_kvargs rte_telemetry rte_net rte_meter
        pthread
)
add_executable(linux_tcp_server examples/linux_tcp_server.c)
