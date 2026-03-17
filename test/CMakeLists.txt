cmake_minimum_required(VERSION 3.17)
project(fnp-test C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")

# dpdk
find_package(PkgConfig REQUIRED)

# 查找DPDK库（REQUIRED表示必需）
#set(ENV{PKG_CONFIG_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../deps/dpdk/lib/x86_64-linux-gnu/pkgconfig:$ENV{PKG_CONFIG_PATH}")
#pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)
#include_directories(${DPDK_INCLUDE_DIRS})
#link_directories(${DPDK_LIBRARY_DIRS})
#message(STATUS "DPDK_VERSION: ${DPDK_VERSION}")
#message(STATUS "DPDK Include directories: ${DPDK_INCLUDE_DIRS}")
#message(STATUS "DPDK Libraries: ${DPDK_LIBRARIES}")
#message(STATUS "DPDK Library directories: ${DPDK_LIBRARY_DIRS}")
#message(STATUS "DPDK_CFLAGS: ${DPDK_CFLAGS}")
#message(STATUS "DPDK_STATIC_LIBRARIES: ${DPDK_STATIC_LIBRARIES}")

set(DPDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../deps/dpdk")
set(DPDK_LIB_DIR "${DPDK_DIR}/lib")
if(DEFINED CMAKE_LIBRARY_ARCHITECTURE AND EXISTS "${DPDK_DIR}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
    set(DPDK_LIB_DIR "${DPDK_DIR}/lib/${CMAKE_LIBRARY_ARCHITECTURE}")
elseif(EXISTS "${DPDK_DIR}/lib64")
    set(DPDK_LIB_DIR "${DPDK_DIR}/lib64")
endif()
message(STATUS "DPDK_DIR: ${DPDK_DIR}")
include_directories(${DPDK_DIR}/include)
link_directories(${DPDK_LIB_DIR})
set(DPDK_LIBRARIES "rte_pdump;rte_timer;rte_hash;rte_cmdline;rte_pci;rte_ethdev;rte_mbuf;rte_mempool;rte_rcu;rte_ring;rte_eal")

# fnp api库
link_directories(../cmake-build-debug)
include_directories(../inc)

add_executable(fnp_udp_client
        ./fnp/fnp_udp_client.c
)
target_link_libraries(fnp_udp_client
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)

add_executable(fnp_udp_server
        ./fnp/fnp_udp_server.c
)
target_link_libraries(fnp_udp_server
        fnp-api
        -pthread -lm -ldl -lnuma -lpcap
        ${DPDK_LIBRARIES}
)
