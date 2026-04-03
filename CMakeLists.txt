cmake_minimum_required(VERSION 3.17)

project(fnp LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_SKIP_RPATH TRUE)
add_compile_options(-mssse3)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)

set(FNP_ENABLE_DEBUG_LOGS 0)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(FNP_ENABLE_DEBUG_LOGS 1)
endif()

set(DPDK_DIR "/opt/dpdk" CACHE PATH "DPDK installation prefix")
option(FNP_DAEMON_STATIC_DPDK "Link fnp-daemon with bundled static DPDK libraries for TAP + ixgbe" ON)
set(DPDK_INCLUDE_DIR "${DPDK_DIR}/include")
set(DPDK_LIB_DIR "${DPDK_DIR}/lib")
if(DEFINED CMAKE_LIBRARY_ARCHITECTURE AND EXISTS "${DPDK_DIR}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
    set(DPDK_LIB_DIR "${DPDK_DIR}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
elseif(EXISTS "${DPDK_DIR}/lib64")
    set(DPDK_LIB_DIR "${DPDK_DIR}/lib64")
endif()

if(NOT EXISTS "${DPDK_INCLUDE_DIR}")
    message(FATAL_ERROR "DPDK include directory not found: ${DPDK_INCLUDE_DIR}")
endif()

if(NOT EXISTS "${DPDK_LIB_DIR}")
    message(FATAL_ERROR "DPDK library directory not found: ${DPDK_LIB_DIR}")
endif()

set(FNP_CONF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/go")
set(FNP_CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/k8s/conf")

message(STATUS "DPDK_DIR: ${DPDK_DIR}")
message(STATUS "DPDK_INCLUDE_DIR: ${DPDK_INCLUDE_DIR}")
message(STATUS "DPDK_LIB_DIR: ${DPDK_LIB_DIR}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "FNP_ENABLE_DEBUG_LOGS: ${FNP_ENABLE_DEBUG_LOGS}")
message(STATUS "FNP_DAEMON_STATIC_DPDK: ${FNP_DAEMON_STATIC_DPDK}")
message(STATUS "FNP_CONF_DIR: ${FNP_CONF_DIR}")
message(STATUS "FNP_CONFIG_DIR: ${FNP_CONFIG_DIR}")

set(FNP_API_SOURCES
        src/common/fnp_ring.c
        src/common/fnp_list.c
        src/api/fnp_frontend.c
        src/api/fnp_socket.c
        src/api/fnp_epoll.c
)

set(FNP_DAEMON_DPDK_BUNDLE_OBJ "${CMAKE_CURRENT_BINARY_DIR}/fnp_daemon_dpdk_bundle.o")

set(FNP_CONF_LIBRARY "${FNP_CONF_DIR}/libfnp-conf.a")
set(FNP_CONF_HEADER "${FNP_CONF_DIR}/libfnp-conf.h")
set(FNP_CONF_GO_DEPENDS
        "${FNP_CONF_DIR}/build.sh"
        "${FNP_CONF_DIR}/go.mod"
        "${FNP_CONF_DIR}/main.go"
)
if(EXISTS "${FNP_CONF_DIR}/go.sum")
    list(APPEND FNP_CONF_GO_DEPENDS "${FNP_CONF_DIR}/go.sum")
endif()

add_custom_command(
        OUTPUT
        "${FNP_CONF_LIBRARY}"
        "${FNP_CONF_HEADER}"
        COMMAND bash "${FNP_CONF_DIR}/build.sh"
        WORKING_DIRECTORY "${FNP_CONF_DIR}"
        DEPENDS ${FNP_CONF_GO_DEPENDS}
        COMMENT "Building fnp Go config parser"
        VERBATIM
)

add_custom_target(fnp-conf-go
        DEPENDS
        "${FNP_CONF_LIBRARY}"
        "${FNP_CONF_HEADER}"
)

set(FNP_CC_ALGO_FILES
        src/daemon/cc/cc_internal.c
        src/daemon/cc/cubic.c
        src/daemon/cc/fnp_cc.c
)

set(FNP_DAEMON_SOURCES
        src/common/fnp_splay.c
        src/common/fnp_list.c
        src/common/fnp_ring.c
        src/daemon/common/rbtree.c
        src/daemon/common/hash.c
        src/daemon/udp/udp.c
        src/daemon/ip/ipv4.c
        src/daemon/ip/route.c
        src/daemon/icmp/icmp.c
        src/daemon/arp/arp.c
        src/daemon/ether/ether.c
        src/daemon/network/fnp_network.c
        src/daemon/network/flow_table.c
        src/daemon/fsocket.c
        src/daemon/raw.c
        src/daemon/tun.c
        src/daemon/tap.c
        src/daemon/fnp_worker.c
        src/common/fnp_msg.c
        src/daemon/fnp_context.c
        src/daemon/fnp_master.c
        src/daemon/main.c
        src/daemon/fapi.c
)

set(FNP_DAEMON_INCLUDE_DIRS
        "${CMAKE_CURRENT_SOURCE_DIR}/inc"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/network"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/udp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/ip"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/icmp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/ether"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/daemon/arp"
        "${DPDK_INCLUDE_DIR}"
        "${FNP_CONF_DIR}"
)

add_executable(fnp-daemon
        ${FNP_DAEMON_SOURCES}
)
add_dependencies(fnp-daemon fnp-conf-go)

target_include_directories(fnp-daemon PRIVATE
        ${FNP_DAEMON_INCLUDE_DIRS}
)
target_compile_definitions(fnp-daemon PRIVATE
        FNP_ENABLE_DEBUG_LOGS=${FNP_ENABLE_DEBUG_LOGS}
)

if(FNP_DAEMON_STATIC_DPDK)
    add_custom_command(
            OUTPUT "${FNP_DAEMON_DPDK_BUNDLE_OBJ}"
            COMMAND ${CMAKE_LINKER} -r -o "${FNP_DAEMON_DPDK_BUNDLE_OBJ}"
                    --whole-archive
                    "${DPDK_LIB_DIR}/librte_pdump.a"
                    "${DPDK_LIB_DIR}/librte_timer.a"
                    "${DPDK_LIB_DIR}/librte_hash.a"
                    "${DPDK_LIB_DIR}/librte_ethdev.a"
                    "${DPDK_LIB_DIR}/librte_net_tap.a"
                    "${DPDK_LIB_DIR}/librte_net_ixgbe.a"
                    "${DPDK_LIB_DIR}/librte_bus_vdev.a"
                    "${DPDK_LIB_DIR}/librte_bus_pci.a"
                    "${DPDK_LIB_DIR}/librte_pci.a"
                    "${DPDK_LIB_DIR}/librte_net.a"
                    "${DPDK_LIB_DIR}/librte_meter.a"
                    "${DPDK_LIB_DIR}/librte_bpf.a"
                    "${DPDK_LIB_DIR}/librte_pcapng.a"
                    "${DPDK_LIB_DIR}/librte_gso.a"
                    "${DPDK_LIB_DIR}/librte_rcu.a"
                    "${DPDK_LIB_DIR}/librte_security.a"
                    "${DPDK_LIB_DIR}/librte_cryptodev.a"
                    "${DPDK_LIB_DIR}/librte_mempool_ring.a"
                    "${DPDK_LIB_DIR}/librte_eal.a"
                    "${DPDK_LIB_DIR}/librte_ring.a"
                    "${DPDK_LIB_DIR}/librte_mempool.a"
                    "${DPDK_LIB_DIR}/librte_mbuf.a"
                    "${DPDK_LIB_DIR}/librte_kvargs.a"
                    "${DPDK_LIB_DIR}/librte_telemetry.a"
                    --no-whole-archive
            DEPENDS
                    "${DPDK_LIB_DIR}/librte_pdump.a"
                    "${DPDK_LIB_DIR}/librte_timer.a"
                    "${DPDK_LIB_DIR}/librte_hash.a"
                    "${DPDK_LIB_DIR}/librte_ethdev.a"
                    "${DPDK_LIB_DIR}/librte_net_tap.a"
                    "${DPDK_LIB_DIR}/librte_net_ixgbe.a"
                    "${DPDK_LIB_DIR}/librte_bus_vdev.a"
                    "${DPDK_LIB_DIR}/librte_bus_pci.a"
                    "${DPDK_LIB_DIR}/librte_pci.a"
                    "${DPDK_LIB_DIR}/librte_net.a"
                    "${DPDK_LIB_DIR}/librte_meter.a"
                    "${DPDK_LIB_DIR}/librte_bpf.a"
                    "${DPDK_LIB_DIR}/librte_pcapng.a"
                    "${DPDK_LIB_DIR}/librte_gso.a"
                    "${DPDK_LIB_DIR}/librte_rcu.a"
                    "${DPDK_LIB_DIR}/librte_security.a"
                    "${DPDK_LIB_DIR}/librte_cryptodev.a"
                    "${DPDK_LIB_DIR}/librte_mempool_ring.a"
                    "${DPDK_LIB_DIR}/librte_eal.a"
                    "${DPDK_LIB_DIR}/librte_ring.a"
                    "${DPDK_LIB_DIR}/librte_mempool.a"
                    "${DPDK_LIB_DIR}/librte_mbuf.a"
                    "${DPDK_LIB_DIR}/librte_kvargs.a"
                    "${DPDK_LIB_DIR}/librte_telemetry.a"
            COMMAND_EXPAND_LISTS
            COMMENT "Bundling required static DPDK objects for fnp-daemon (tap + ixgbe)"
            VERBATIM
    )

    add_custom_target(fnp-daemon-dpdk-bundle
            DEPENDS "${FNP_DAEMON_DPDK_BUNDLE_OBJ}"
    )
    add_dependencies(fnp-daemon fnp-daemon-dpdk-bundle)

    target_link_libraries(fnp-daemon PRIVATE
            ${FNP_CONF_LIBRARY}
            ${FNP_DAEMON_DPDK_BUNDLE_OBJ}
            pthread
            ${CMAKE_DL_LIBS}
            m
            numa
            pcap
            nl-3
            nl-route-3
            dbus-1
            atomic
    )
    target_link_options(fnp-daemon PRIVATE
            "-Wl,--export-dynamic"
    )
else()
    target_link_libraries(fnp-daemon PRIVATE
            ${FNP_CONF_LIBRARY}
            "-Wl,--no-as-needed"
            "${DPDK_LIB_DIR}/librte_pdump.so"
            "${DPDK_LIB_DIR}/librte_timer.so"
            "${DPDK_LIB_DIR}/librte_hash.so"
            "${DPDK_LIB_DIR}/librte_ethdev.so"
            "${DPDK_LIB_DIR}/librte_net_tap.so"
            "${DPDK_LIB_DIR}/librte_net_ixgbe.so"
            "${DPDK_LIB_DIR}/librte_bus_vdev.so"
            "${DPDK_LIB_DIR}/librte_bus_pci.so"
            "${DPDK_LIB_DIR}/librte_pci.so"
            "${DPDK_LIB_DIR}/librte_security.so"
            "${DPDK_LIB_DIR}/librte_cryptodev.so"
            "${DPDK_LIB_DIR}/librte_net.so"
            "${DPDK_LIB_DIR}/librte_meter.so"
            "${DPDK_LIB_DIR}/librte_mempool_ring.so"
            "${DPDK_LIB_DIR}/librte_eal.so"
            "${DPDK_LIB_DIR}/librte_ring.so"
            "${DPDK_LIB_DIR}/librte_mempool.so"
            "${DPDK_LIB_DIR}/librte_mbuf.so"
            "${DPDK_LIB_DIR}/librte_kvargs.so"
            "${DPDK_LIB_DIR}/librte_telemetry.so"
            "-Wl,--as-needed"
            pthread
            ${CMAKE_DL_LIBS}
            m
            numa
            pcap
            atomic
    )
    target_link_options(fnp-daemon PRIVATE
            "-Wl,-rpath-link,${DPDK_LIB_DIR}"
    )
endif()

add_library(fnp-api-obj OBJECT
        ${FNP_API_SOURCES}
)
set_target_properties(fnp-api-obj PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(fnp-api-obj
        PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/inc"
        "${DPDK_INCLUDE_DIR}"
        PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/api"
)
target_compile_definitions(fnp-api-obj PRIVATE
        FNP_ENABLE_DEBUG_LOGS=${FNP_ENABLE_DEBUG_LOGS}
)

add_library(fnp-api SHARED
        $<TARGET_OBJECTS:fnp-api-obj>
)

target_include_directories(fnp-api
        PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/inc"
        "${DPDK_INCLUDE_DIR}"
        PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/api"
)

target_link_libraries(fnp-api
        PUBLIC
        "${DPDK_LIB_DIR}/librte_eal.so"
        "${DPDK_LIB_DIR}/librte_ring.so"
        "${DPDK_LIB_DIR}/librte_mempool.so"
        "${DPDK_LIB_DIR}/librte_mempool_ring.so"
        "${DPDK_LIB_DIR}/librte_mbuf.so"
        "${DPDK_LIB_DIR}/librte_kvargs.so"
        "${DPDK_LIB_DIR}/librte_telemetry.so"
        PRIVATE
        pthread
        ${CMAKE_DL_LIBS}
        m
        numa
)
target_link_options(fnp-api PRIVATE
        "-Wl,-rpath-link,${DPDK_LIB_DIR}"
        "-Wl,--no-as-needed"
)

set(FNP_API_DPDK_BUNDLE_OBJ "${CMAKE_CURRENT_BINARY_DIR}/fnp_api_dpdk_bundle.o")
set(FNP_API_FAT_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/libfnp-api.a")

add_custom_command(
        OUTPUT "${FNP_API_DPDK_BUNDLE_OBJ}"
        COMMAND ${CMAKE_LINKER} -r -o "${FNP_API_DPDK_BUNDLE_OBJ}"
                --whole-archive
                "${DPDK_LIB_DIR}/librte_eal.a"
                "${DPDK_LIB_DIR}/librte_ring.a"
                "${DPDK_LIB_DIR}/librte_mempool.a"
                "${DPDK_LIB_DIR}/librte_mempool_ring.a"
                "${DPDK_LIB_DIR}/librte_mbuf.a"
                "${DPDK_LIB_DIR}/librte_kvargs.a"
                "${DPDK_LIB_DIR}/librte_telemetry.a"
                --no-whole-archive
        DEPENDS
        "${DPDK_LIB_DIR}/librte_eal.a"
        "${DPDK_LIB_DIR}/librte_ring.a"
        "${DPDK_LIB_DIR}/librte_mempool.a"
        "${DPDK_LIB_DIR}/librte_mempool_ring.a"
        "${DPDK_LIB_DIR}/librte_mbuf.a"
        "${DPDK_LIB_DIR}/librte_kvargs.a"
        "${DPDK_LIB_DIR}/librte_telemetry.a"
        COMMENT "Bundling required DPDK static objects for fnp-api"
        VERBATIM
)

add_custom_command(
        OUTPUT "${FNP_API_FAT_ARCHIVE}"
        COMMAND ${CMAKE_COMMAND} -E rm -f "${FNP_API_FAT_ARCHIVE}"
        COMMAND ${CMAKE_AR} qc "${FNP_API_FAT_ARCHIVE}" $<TARGET_OBJECTS:fnp-api-obj> "${FNP_API_DPDK_BUNDLE_OBJ}"
        COMMAND ${CMAKE_RANLIB} "${FNP_API_FAT_ARCHIVE}"
        DEPENDS
        $<TARGET_OBJECTS:fnp-api-obj>
        "${FNP_API_DPDK_BUNDLE_OBJ}"
        COMMAND_EXPAND_LISTS
        COMMENT "Creating self-contained fnp-api static library"
        VERBATIM
)

add_custom_target(fnp-api-static ALL DEPENDS "${FNP_API_FAT_ARCHIVE}")
