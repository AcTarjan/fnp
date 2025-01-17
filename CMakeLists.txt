cmake_minimum_required(VERSION 3.17)
project(fnp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

# dpdk
include_directories(/opt/dpdk/include)
link_directories(/opt/dpdk/lib64)


include_directories(src/inc)
include_directories(src/sock)
include_directories(src/tcp/inc)
include_directories(src/udp)
include_directories(src/ip)
include_directories(src/common)
include_directories(libs)


link_directories(libs)

# fnp-daemon是一个守护进程，提供一个高性能的网络协议栈，
# 通过fnp-api库提供的接口，供上层应用调用
add_executable(fnp-daemon
        src/common/rbtree.c
        src/common/fnp_ring.c
        src/common/fnp_pring.c
        src/tcp/tcp_timer.c
        src/tcp/tcp_sock.c
        src/tcp/tcp_in.c
        src/tcp/tcp_out.c
        src/tcp/tcp_ofo.c
        src/tcp/tcp.c
        src/tcp/tcp_api.c
        src/fnp_init.c
        src/ip/fnp_ipv4.c
        src/fnp_icmp.c
        src/fnp_arp.c
        src/fnp_ether.c
        src/fnp_worker.c
        src/common/hash.c
        src/common/hash.h
        src/udp/fnp_udp.c
        src/sock/ipv4_5tuple.c
        src/sock/ipv4_5tuple.h
        src/sock/fnp_sock.c
        src/fnp_msg.c
        src/main.c
)
#target_compile_definitions(fnp-daemon PRIVATE USE_DPDK)
target_link_libraries(fnp-daemon
        rte_hash rte_ip_frag rte_timer
        rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal
        rte_kvargs rte_telemetry rte_net rte_meter
        pthread libfnp-conf.so
)

# fnp的接口库，通过此接口库可以调用fnp的功能
add_library(fnp-api SHARED
        api/fnp_api.c
        api/fnp_socket.c
)

add_executable(fnp_api_test api/main.c)
target_link_libraries(fnp_api_test
        fnp-api
        rte_mempool rte_mbuf rte_ring rte_eal
)

add_executable(test_conf examples/test_conf.c)
target_link_libraries(test_conf libfnp-conf.so)


add_executable(test_hash examples/test_hash.c)


add_executable(test_ring examples/test_ring.c src/common/fnp_pring.c)
target_link_libraries(test_ring pthread)


add_executable(tcp_server examples/fnp_tcp_server.c)
target_link_libraries(tcp_server fnp-api
        rte_hash rte_ip_frag rte_timer
        rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal
        rte_kvargs rte_telemetry rte_net rte_meter
        pthread libfnp-conf.so
)


add_executable(linux_tcp_server examples/linux_tcp_server.c)


#进程间通信
add_executable(ipc_slave examples/ipc_slave.c)
target_link_libraries(ipc_slave rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal)
set_target_properties(ipc_slave PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deploy/k8s)
set_target_properties(ipc_slave PROPERTIES OUTPUT_NAME dpdkSlaveApp)

add_executable(ipc_master examples/ipc_master.c)
target_link_libraries(ipc_master rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal)
