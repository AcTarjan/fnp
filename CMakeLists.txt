cmake_minimum_required(VERSION 3.17)
project(fnp C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

# dpdk
set(DPDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/dpdk")
set(DPDK_LIB_DIR "${DPDK_DIR}/lib")
if(DEFINED CMAKE_LIBRARY_ARCHITECTURE AND EXISTS "${DPDK_DIR}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
    set(DPDK_LIB_DIR "${DPDK_DIR}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
elseif(EXISTS "${DPDK_DIR}/lib64")
    set(DPDK_LIB_DIR "${DPDK_DIR}/lib64")
endif()
message(STATUS "DPDK_DIR: ${DPDK_DIR}")
message(STATUS "DPDK_LIB_DIR: ${DPDK_LIB_DIR}")
include_directories(${DPDK_DIR}/include)
link_directories(${DPDK_LIB_DIR})
set(DPDK_LIBRARIES "rte_pdump;rte_timer;rte_hash;rte_cmdline;rte_pci;rte_ethdev;rte_mbuf;rte_mempool;rte_rcu;rte_ring;rte_eal")

# picotls
set(PICOTLS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/picotls")
message(STATUS "PICOTLS_DIR: ${PICOTLS_DIR}")
include_directories(${PICOTLS_DIR}/include)
link_directories(${PICOTLS_DIR}/lib)
# picotls-openssl;picotls-fusion是可选的, picotls-openssl依赖OpenSSL, picotls-fusion依赖Fusion库
set(PICOTLS_LIBRARIES "picotls-core;picotls-openssl;picotls-fusion;picotls-minicrypto")
#    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_FUSION)
#    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_OPENSSL)
set(OPENSSL_LIBRARIES "ssl;crypto")

# conf
set(FNP_CONF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/conf")
message(STATUS "FNP_CONF_DIR: ${FNP_CONF_DIR}")
include_directories(${FNP_CONF_DIR})
link_directories(${FNP_CONF_DIR})

set(FNP_CC_ALGO_FILES
        src/daemon/cc/cc_internal.c
        src/daemon/cc/cubic.c
        src/daemon/cc/fnp_cc.c
)

set(FNP_TCP_FILES_DIR "src/daemon/tcp")
set(FNP_TCP_FILES
        ${FNP_TCP_FILES_DIR}/tcp_sock.c
        ${FNP_TCP_FILES_DIR}/tcp_in.c
        ${FNP_TCP_FILES_DIR}/tcp_out.c
        ${FNP_TCP_FILES_DIR}/tcp_ofo.c
        ${FNP_TCP_FILES_DIR}/tcp_timer.c
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

# fnp-daemon是一个守护进程，提供一个高性能的网络协议栈
add_executable(fnp-daemon
        src/common/fnp_splay.c
        src/common/fnp_list.c
        src/common/fnp_ring.c
        src/daemon/common/rbtree.c
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
        src/daemon/fapi.c
)

target_include_directories(fnp-daemon PRIVATE inc)
target_include_directories(fnp-daemon PRIVATE src/common)
target_include_directories(fnp-daemon PRIVATE src/daemon)
target_include_directories(fnp-daemon PRIVATE src/daemon/common)
target_include_directories(fnp-daemon PRIVATE src/daemon/cc)
target_include_directories(fnp-daemon PRIVATE src/daemon/iface)
target_include_directories(fnp-daemon PRIVATE ${FNP_TCP_FILES_DIR})
target_include_directories(fnp-daemon PRIVATE ${FNP_QUIC_FILES_DIR})
target_include_directories(fnp-daemon PRIVATE src/daemon/udp)
target_include_directories(fnp-daemon PRIVATE src/daemon/ip)
target_include_directories(fnp-daemon PRIVATE src/daemon/icmp)
target_include_directories(fnp-daemon PRIVATE src/daemon/ether)
target_include_directories(fnp-daemon PRIVATE src/daemon/arp)
#target_compile_definitions(fnp-daemon PRIVATE USE_DPDK)

target_link_libraries(fnp-daemon
        PRIVATE
        ${OPENSSL_LIBRARIES}
        fnp-conf
        PUBLIC
        ${PICOTLS_LIBRARIES}
        -pthread -lm -ldl -lnuma -lpcap -latomic
        ${DPDK_LIBRARIES}
)

# fnp的接口库，通过此接口库可以调用fnp的功能
add_library(fnp-api SHARED
        src/common/fnp_ring.c
        src/common/fnp_list.c
        src/api/fnp_frontend.c
        #        src/api/fnp_quic.c
        src/api/fsocket.c
)
target_include_directories(fnp-api PRIVATE src/common)
target_include_directories(fnp-api PRIVATE src/api)
target_include_directories(fnp-api PRIVATE inc)

add_executable(fnp_udp_client
        ./test/fnp/fnp_udp_client.c
)
target_include_directories(fnp_udp_client PRIVATE inc)
target_link_libraries(fnp_udp_client
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)

add_executable(fnp_udp_server
        ./test/fnp/fnp_udp_server.c
)
target_include_directories(fnp_udp_server PRIVATE inc)
target_link_libraries(fnp_udp_server
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)
