project(lcc C)
cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_BINARY_DIR}/third
    ${CMAKE_CURRENT_BINARY_DIR}/third/libbpf
)

add_subdirectory(lcc)
add_subdirectory(third)
