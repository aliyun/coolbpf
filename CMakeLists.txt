project(lcc C)
cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_BINARY_DIR}/third
    ${CMAKE_CURRENT_BINARY_DIR}/third/libbpf
    ${CMAKE_CURRENT_SOURCE_DIR}/third/libbpf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/libbpf/include/uapi
)

add_subdirectory(btf)
add_subdirectory(lcc)
add_subdirectory(third)
