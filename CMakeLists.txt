cmake_minimum_required(VERSION 3.17)

project(fnp LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_SKIP_RPATH TRUE)
add_compile_options(-mssse3)

set(DPDK_DIR "/opt/dpdk" CACHE PATH "DPDK installation prefix")
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
set(FNP_CONFIG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/conf")

message(STATUS "DPDK_DIR: ${DPDK_DIR}")
message(STATUS "DPDK_INCLUDE_DIR: ${DPDK_INCLUDE_DIR}")
message(STATUS "DPDK_LIB_DIR: ${DPDK_LIB_DIR}")
message(STATUS "FNP_CONF_DIR: ${FNP_CONF_DIR}")
message(STATUS "FNP_CONFIG_DIR: ${FNP_CONFIG_DIR}")

function(fnp_find_local_library out_var lib_name search_dir)
    unset(_library_path CACHE)
    unset(_library_path)
    find_library(_library_path
            NAMES ${lib_name}
            PATHS "${search_dir}"
            NO_DEFAULT_PATH
            REQUIRED)
    set(${out_var} "${_library_path}" PARENT_SCOPE)
endfunction()

fnp_find_local_library(DPDK_LIB_EAL rte_eal "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_RING rte_ring "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_MEMPOOL rte_mempool "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_MEMPOOL_RING rte_mempool_ring "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_MBUF rte_mbuf "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_HASH rte_hash "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_TIMER rte_timer "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_ETHDEV rte_ethdev "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_PDUMP rte_pdump "${DPDK_LIB_DIR}")
fnp_find_local_library(DPDK_LIB_NET_TAP rte_net_tap "${DPDK_LIB_DIR}")

set(FNP_API_DPDK_LIBRARIES
        ${DPDK_LIB_EAL}
        ${DPDK_LIB_RING}
        ${DPDK_LIB_MEMPOOL}
        ${DPDK_LIB_MEMPOOL_RING}
        ${DPDK_LIB_MBUF}
)

set(FNP_DAEMON_DPDK_LIBRARIES
        ${DPDK_LIB_PDUMP}
        ${DPDK_LIB_TIMER}
        ${DPDK_LIB_HASH}
        ${DPDK_LIB_ETHDEV}
        ${DPDK_LIB_NET_TAP}
        ${DPDK_LIB_MEMPOOL_RING}
        ${FNP_API_DPDK_LIBRARIES}
)

set(FNP_DPDK_LINK_OPTIONS
        "-Wl,-rpath-link,${DPDK_LIB_DIR}"
)

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

set(FNP_DAEMON_LINK_LIBRARIES
        ${FNP_CONF_LIBRARY}
        "-Wl,--no-as-needed"
        ${FNP_DAEMON_DPDK_LIBRARIES}
        "-Wl,--as-needed"
        pthread
        ${CMAKE_DL_LIBS}
        m
        numa
        pcap
        atomic
)

add_executable(fnp-daemon
        ${FNP_DAEMON_SOURCES}
)
add_dependencies(fnp-daemon fnp-conf-go)

target_include_directories(fnp-daemon PRIVATE
        ${FNP_DAEMON_INCLUDE_DIRS}
)

target_link_libraries(fnp-daemon PRIVATE
        ${FNP_DAEMON_LINK_LIBRARIES}
)
target_link_options(fnp-daemon PRIVATE ${FNP_DPDK_LINK_OPTIONS})

add_library(fnp-api SHARED
        src/common/fnp_ring.c
        src/common/fnp_list.c
        src/api/fnp_frontend.c
        src/api/fnp_socket.c
        src/api/fnp_epoll.c
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
        ${FNP_API_DPDK_LIBRARIES}
        PRIVATE
        pthread
        ${CMAKE_DL_LIBS}
        m
        numa
)
target_link_options(fnp-api PRIVATE
        ${FNP_DPDK_LINK_OPTIONS}
        "-Wl,--no-as-needed"
)
