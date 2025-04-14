cmake_minimum_required(VERSION 3.17)
project(fnp C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

# dpdk
include_directories(/opt/dpdk/include)
link_directories(/opt/dpdk/lib64)


include_directories(src/common)
include_directories(src/daemon)
include_directories(src/daemon/iface)
include_directories(src/daemon/sock)
include_directories(src/daemon/tcp)
include_directories(src/daemon/udp)
include_directories(src/daemon/ip)
include_directories(src/daemon/icmp)
include_directories(src/daemon/ether)
include_directories(src/daemon/arp)
include_directories(src/daemon/common)
include_directories(libs)
include_directories(src/fnp)


link_directories(libs)

# fnp-daemon是一个守护进程，提供一个高性能的网络协议栈，
# 通过fnp-api库提供的接口，供用户程序调用
add_executable(fnp-daemon
        src/daemon/fnp_socket.c
        src/daemon/fnp_msg.c
        src/daemon/common/rbtree.c
        src/daemon/common/fnp_ring.c
        src/daemon/common/fnp_pring.c
        src/daemon/common/hash.c
        src/daemon/tcp/tcp_timer.c
        src/daemon/tcp/tcp_sock.c
        src/daemon/tcp/tcp_in.c
        src/daemon/tcp/tcp_out.c
        src/daemon/tcp/tcp_ofo.c
        src/daemon/tcp/tcp.c
        src/daemon/udp/udp.c
        src/daemon/ip/ipv4.c
        src/daemon/icmp/icmp.c
        src/daemon/arp/arp.c
        src/daemon/ether/ether.c
        src/daemon/iface/fnp_iface.c
        src/daemon/fnp_worker.c
        src/daemon/fnp_context.c
        src/daemon/fnp_frontend.c
        src/daemon/ip/route.c
        src/daemon/main.c
)
#target_compile_definitions(fnp-daemon PRIVATE USE_DPDK)
target_link_libraries(fnp-daemon
        -pthread -lm -ldl -lnuma -lpcap libfnp-conf.so
        -lrte_node -lrte_graph -lrte_pipeline -lrte_table -lrte_pdump
        -lrte_port -lrte_fib -lrte_ipsec -lrte_vhost -lrte_stack -lrte_security
        -lrte_sched -lrte_reorder -lrte_rib -lrte_dmadev -lrte_regexdev -lrte_rawdev
        -lrte_power -lrte_pcapng -lrte_member -lrte_lpm -lrte_latencystats
        -lrte_jobstats -lrte_ip_frag -lrte_gso -lrte_gro -lrte_gpudev -lrte_eventdev
        -lrte_efd -lrte_distributor -lrte_cryptodev -lrte_compressdev
        -lrte_cfgfile -lrte_bpf -lrte_bitratestats -lrte_bbdev -lrte_acl
        -lrte_timer -lrte_hash -lrte_metrics -lrte_cmdline -lrte_pci -lrte_ethdev
        -lrte_meter -lrte_net -lrte_mbuf -lrte_mempool -lrte_rcu -lrte_ring
        -lrte_eal -lrte_telemetry -lrte_kvargs
)

# fnp的接口库，通过此接口库可以调用fnp的功能
add_library(fnp-api SHARED
        src/fnp/fnp.c 
)

add_executable(fnp_api_test src/fnp/fnp.c src/fnp/main.c)
target_link_libraries(fnp_api_test
        -pthread -lm -ldl -lnuma -lpcap
        -lrte_node -lrte_graph -lrte_pipeline -lrte_table -lrte_pdump -lrte_port -lrte_fib -lrte_ipsec -lrte_vhost -lrte_stack -lrte_security -lrte_sched -lrte_reorder -lrte_rib -lrte_dmadev -lrte_regexdev -lrte_rawdev -lrte_power -lrte_pcapng -lrte_member -lrte_lpm -lrte_latencystats -lrte_jobstats -lrte_ip_frag -lrte_gso -lrte_gro -lrte_gpudev -lrte_eventdev -lrte_efd -lrte_distributor -lrte_cryptodev -lrte_compressdev -lrte_cfgfile -lrte_bpf -lrte_bitratestats -lrte_bbdev -lrte_acl -lrte_timer -lrte_hash -lrte_metrics -lrte_cmdline -lrte_pci -lrte_ethdev -lrte_meter -lrte_net -lrte_mbuf -lrte_mempool -lrte_rcu -lrte_ring -lrte_eal -lrte_telemetry -lrte_kvargs
)

add_executable(client examples/client.c)
add_executable(server examples/server.c)

# add_executable(tcp_client examples/tcp_client/tcp_client.c)
# add_executable(tcp_server examples/tcp_server/tcp_server.c)

# add_executable(test_conf examples/other/other/test_conf.c)
# target_link_libraries(test_conf libfnp-conf.so)


# add_executable(test_hash examples/test_hash.c)
# add_executable(test_ring examples/test_ring.c src/daemon/common/fnp_pring.c)
# target_link_libraries(test_ring pthread)




#进程间通信
# add_executable(ipc_slave examples/ipc_slave.c)
# target_link_libraries(ipc_slave rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal)
# set_target_properties(ipc_slave PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deploy/k8s)
# set_target_properties(ipc_slave PROPERTIES OUTPUT_NAME dpdkSlaveApp)

# add_executable(ipc_master examples/ipc_master.c)
# target_link_libraries(ipc_master rte_mempool rte_mbuf rte_ring rte_ethdev rte_eal)
