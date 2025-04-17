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
include_directories(src/daemon/picoquic)
include_directories(libs)
include_directories(src/fnp)


link_directories(libs)

set(PICOQUIC_LIBRARY_FILES
    src/daemon/picoquic/bbr.c
    src/daemon/picoquic/bytestream.c
    src/daemon/picoquic/cc_common.c
    src/daemon/picoquic/config.c
    src/daemon/picoquic/cubic.c
    src/daemon/picoquic/fastcc.c
    src/daemon/picoquic/frames.c
    src/daemon/picoquic/intformat.c
    src/daemon/picoquic/logger.c
    src/daemon/picoquic/logwriter.c
    src/daemon/picoquic/newreno.c
    src/daemon/picoquic/packet.c
    src/daemon/picoquic/performance_log.c
    src/daemon/picoquic/picohash.c
    src/daemon/picoquic/picoquic_lb.c
    src/daemon/picoquic/picosocks.c
    src/daemon/picoquic/picosplay.c
    src/daemon/picoquic/port_blocking.c
    src/daemon/picoquic/prague.c
    src/daemon/picoquic/quicctx.c
    src/daemon/picoquic/sacks.c
    src/daemon/picoquic/sender.c
    src/daemon/picoquic/sim_link.c
    # src/daemon/picoquic/sockloop.c
    src/daemon/picoquic/spinbit.c
    src/daemon/picoquic/ticket_store.c
    src/daemon/picoquic/token_store.c
    src/daemon/picoquic/tls_api.c
    src/daemon/picoquic/transport.c
    src/daemon/picoquic/unified_log.c
    src/daemon/picoquic/util.c
    src/daemon/picoquic/quic.c)

set(PICOQUIC_CORE_HEADERS
        src/daemon/picoquic/picoquic.h
        src/daemon/picoquic/picosocks.h
        src/daemon/picoquic/picoquic_utils.h
        src/daemon/picoquic/picoquic_packet_loop.h
        src/daemon/picoquic/picoquic_unified_log.h
        src/daemon/picoquic/picoquic_logger.h
        src/daemon/picoquic/picoquic_binlog.h
        src/daemon/picoquic/picoquic_config.h
        src/daemon/picoquic/picoquic_lb.h
)

OPTION(PICOQUIC_FETCH_PTLS "Fetch PicoTLS during configuration" OFF)
if(PICOQUIC_FETCH_PTLS)
    include(FetchContent)
    FetchContent_Declare(picotls
        GIT_REPOSITORY      https://github.com/h2o/picotls.git
        GIT_TAG             7d294ab4f2e0ed749b4bcfaf533225a4e0c096f7)
    FetchContent_MakeAvailable(picotls)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PTLS REQUIRED)
message(STATUS "picotls/include: ${PTLS_INCLUDE_DIRS}" )
message(STATUS "picotls libraries: ${PTLS_LIBRARIES}" )

OPTION(PTLS_WITH_FUSION "build 'fusion' AES-GCM engine" ${PTLS_WITH_FUSION_DEFAULT})
if(PTLS_WITH_FUSION)
    message(STATUS "PTLS Fusion is enabled")
else()
    message(STATUS "PTLS compiled without support for Fusion")
    list(APPEND PICOQUIC_COMPILE_DEFINITIONS PTLS_WITHOUT_FUSION)
endif()

find_package(OpenSSL REQUIRED)
message(STATUS "root: ${OPENSSL_ROOT_DIR}")
message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
message(STATUS "CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")


include_directories(${PTLS_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
# fnp-daemon是一个守护进程，提供一个高性能的网络协议栈，
# 通过fnp-api库提供的接口，供用户程序调用
add_executable(fnp-daemon
        ${PICOQUIC_LIBRARY_FILES}
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
    PRIVATE
        ${OPENSSL_LIBRARIES}
    PUBLIC
        ${PTLS_LIBRARIES}
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

add_executable(fnp_api_test 
    src/fnp/fnp.c
    src/fnp/quic_client.c
    src/fnp/main.c)

target_link_libraries(fnp_api_test
    PRIVATE
        ${OPENSSL_LIBRARIES}
    PUBLIC
        ${PTLS_LIBRARIES}
        -pthread -lm -ldl -lnuma -lpcap
        -lrte_node -lrte_graph -lrte_pipeline -lrte_table -lrte_pdump -lrte_port -lrte_fib -lrte_ipsec -lrte_vhost -lrte_stack -lrte_security -lrte_sched -lrte_reorder -lrte_rib -lrte_dmadev -lrte_regexdev -lrte_rawdev -lrte_power -lrte_pcapng -lrte_member -lrte_lpm -lrte_latencystats -lrte_jobstats -lrte_ip_frag -lrte_gso -lrte_gro -lrte_gpudev -lrte_eventdev -lrte_efd -lrte_distributor -lrte_cryptodev -lrte_compressdev -lrte_cfgfile -lrte_bpf -lrte_bitratestats -lrte_bbdev -lrte_acl -lrte_timer -lrte_hash -lrte_metrics -lrte_cmdline -lrte_pci -lrte_ethdev -lrte_meter -lrte_net -lrte_mbuf -lrte_mempool -lrte_rcu -lrte_ring -lrte_eal -lrte_telemetry -lrte_kvargs
)

add_executable(client examples/client.c)
add_executable(server examples/server.c)
