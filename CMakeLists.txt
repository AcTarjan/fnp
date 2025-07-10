cmake_minimum_required(VERSION 3.17)
project(fnp C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

# dpdk
set(DPDK_DIR "/opt/dpdk")
message(STATUS "DPDK_DIR: ${DPDK_DIR}")
include_directories(${DPDK_DIR}/include)
link_directories(${DPDK_DIR}/lib64)
set(DPDK_LIBRARIES "rte_pdump;rte_timer;rte_hash;rte_cmdline;rte_pci;rte_ethdev;rte_mbuf;rte_mempool;rte_rcu;rte_ring;rte_eal")

# picotls
set(PICOTLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dep_libs/picotls")
message(STATUS "PICOTLS_DIR: ${PICOTLS_DIR}")
include_directories(${PICOTLS_DIR}/include)
link_directories(${PICOTLS_DIR}/lib)
# picotls-openssl;picotls-fusion是可选的, picotls-openssl依赖OpenSSL, picotls-fusion依赖Fusion库
set(PICOTLS_LIBRARIES "picotls-core;picotls-openssl;picotls-fusion;picotls-minicrypto")
#    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_FUSION)
#    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_OPENSSL)
set(OPENSSL_LIBRARIES "ssl;crypto")

# conf
include_directories(dep_libs/conf)
link_directories(dep_libs/conf)

set(FNP_CC_ALGO_FILES
        src/daemon/cc/cc_internal.c
        src/daemon/cc/cubic.c
        src/daemon/cc/fnp_cc.c
)

set(FNP_TCP_FILES_DIR "src/daemon/tcp")
set(FNP_TCP_FILES
        ${FNP_TCP_FILES_DIR}/tcp_timer.c
        ${FNP_TCP_FILES_DIR}/tcp_sock.c
        ${FNP_TCP_FILES_DIR}/tcp_in.c
        ${FNP_TCP_FILES_DIR}/tcp_out.c
        ${FNP_TCP_FILES_DIR}/tcp_ofo.c
        ${FNP_TCP_FILES_DIR}/tcp.c
)

set(FNP_QUIC_FILES_DIR "src/daemon/picoquic")
set(FNP_QUIC_FILES
        ${FNP_QUIC_FILES_DIR}/intformat.c
        ${FNP_QUIC_FILES_DIR}/quic_stream.c
        ${FNP_QUIC_FILES_DIR}/quic_frames.c
        ${FNP_QUIC_FILES_DIR}/quic_cc.c
        ${FNP_QUIC_FILES_DIR}/loss_recovery.c
        ${FNP_QUIC_FILES_DIR}/pacing.c
        ${FNP_QUIC_FILES_DIR}/quic_packet.c
        ${FNP_QUIC_FILES_DIR}/paths.c
        ${FNP_QUIC_FILES_DIR}/picohash.c
        ${FNP_QUIC_FILES_DIR}/picoquic_ptls_fusion.c
        ${FNP_QUIC_FILES_DIR}/picoquic_ptls_openssl.c
        ${FNP_QUIC_FILES_DIR}/port_blocking.c
        ${FNP_QUIC_FILES_DIR}/quicctx.c
        ${FNP_QUIC_FILES_DIR}/quic_conn.c
        ${FNP_QUIC_FILES_DIR}/sacks.c
        ${FNP_QUIC_FILES_DIR}/quic_recv.c
        ${FNP_QUIC_FILES_DIR}/quic_sender.c
        ${FNP_QUIC_FILES_DIR}/siphash.c
        ${FNP_QUIC_FILES_DIR}/spinbit.c
        ${FNP_QUIC_FILES_DIR}/ticket_store.c
        ${FNP_QUIC_FILES_DIR}/timing.c
        ${FNP_QUIC_FILES_DIR}/token_store.c
        ${FNP_QUIC_FILES_DIR}/tls_api.c
        ${FNP_QUIC_FILES_DIR}/transport.c
        ${FNP_QUIC_FILES_DIR}/unified_log.c
        ${FNP_QUIC_FILES_DIR}/util.c
        ${FNP_QUIC_FILES_DIR}/quic.c
)

#
include_directories(src/common)
include_directories(src/fnp)
include_directories(src/daemon)
include_directories(src/daemon/cc)
include_directories(src/daemon/iface)
include_directories(${FNP_TCP_FILES_DIR})
include_directories(${FNP_QUIC_FILES_DIR})
include_directories(src/daemon/udp)
include_directories(src/daemon/ip)
include_directories(src/daemon/icmp)
include_directories(src/daemon/ether)
include_directories(src/daemon/arp)
include_directories(src/daemon/common)


# fnp-daemon是一个守护进程，提供一个高性能的网络协议栈，
# 通过fnp-api库提供的接口，供用户程序调用
add_executable(fnp-daemon
        src/common/fnp_splay.c
        src/common/fnp_common.c
        src/common/fnp_pring.c
        src/common/fnp_list.c
        src/daemon/common/rbtree.c
        src/daemon/common/fnp_ring.c
        src/daemon/common/hash.c
        ${FNP_CC_ALGO_FILES}
        ${FNP_QUIC_FILES}
        ${FNP_TCP_FILES}
        src/daemon/udp/udp.c
        src/daemon/ip/ipv4.c
        src/daemon/ip/route.c
        src/daemon/icmp/icmp.c
        src/daemon/arp/arp.c
        src/daemon/ether/ether.c
        src/daemon/iface/fnp_iface.c
        src/daemon/iface/flow_table.c
        src/daemon/fsocket.c
        src/daemon/fnp_worker.c
        src/common/fnp_msg.c
        src/daemon/fnp_context.c
        src/daemon/fnp_master.c
        src/daemon/main.c
)
#target_compile_definitions(fnp-daemon PRIVATE USE_DPDK)

target_link_libraries(fnp-daemon
        PRIVATE
        ${OPENSSL_LIBRARIES}
        PUBLIC
        ${PICOTLS_LIBRARIES}
        -pthread -lm -ldl -lnuma -lpcap -latomic libfnp-conf.so
        ${DPDK_LIBRARIES}
)

# fnp的接口库，通过此接口库可以调用fnp的功能
add_library(fnp-api SHARED
        src/common/fnp_pring.c
        src/common/fnp_list.c
        src/common/fnp_msg.c
        src/common/fnp_common.c
        src/fnp/fnp_frontend.c
        src/fnp/fnp_quic.c
        src/fnp/fnp.c
)

add_executable(fnp_quic_server
        src/demo/fnp_quic_server.c)

target_link_libraries(fnp_quic_server
        fnp-api pthread m dl numa pcap
        ${DPDK_LIBRARIES}
)


add_executable(fnp_quic_client
        src/demo/fnp_quic_client.c)

target_link_libraries(fnp_quic_client
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)

add_executable(local_client
        test/local/client.c)
target_link_libraries(local_client
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)

add_executable(local_server
        test/local/server.c)
target_link_libraries(local_server
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)


add_executable(remote_udp_client
        test/remote_udp/client.c)
target_link_libraries(local_client
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)

add_executable(remote_udp_server
        test/remote_udp/server.c)
target_link_libraries(local_server
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)

add_executable(fnp_ring
        test/fnp_ring/fnp_ring.c)
target_link_libraries(fnp_ring
        -pthread -lm -ldl -lnuma -latomic -lpcap
        ${DPDK_LIBRARIES}
)


add_executable(linux_udp_server
        test/linux/udp_server.c
        src/common/fnp_common.c)
target_link_libraries(linux_udp_server
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)


add_executable(linux_udp_client
        test/linux/udp_client.c
        src/common/fnp_common.c)
target_link_libraries(linux_udp_client
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)