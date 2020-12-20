cmake_minimum_required(VERSION 3.17)
project(untitled C)

set(CMAKE_C_STANDARD 11)

add_executable(send_request main.c cJSON.h cJSON.c send_request.h send_request.c)

file(GLOB server_src
        "server/single-container-server/*.h"
        "server/single-container-server/*.c"
        )

add_executable(server server_listener.c get_server_certs.c get_server_certs.h server_handler.c server_handler.h cJSON.c cJSON.h ${server_src})

add_executable(getcert getcert.c send_request.c send_request.h cJSON.h cJSON.c sha256.c sha256.h)

target_link_libraries(send_request PUBLIC ssl crypto)

target_link_libraries(server PUBLIC ssl crypto)

target_link_libraries(getcert PUBLIC ssl crypto)