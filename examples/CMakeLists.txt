cmake_minimum_required(VERSION 3.17)
project(fnp-example C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mssse3")


add_executable(server 
    socket.c
    server.c
    )

add_executable(client
    socket.c
    client.c
    )