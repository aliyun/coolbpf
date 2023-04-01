project(coolbpf C)
cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}/third
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/${CMAKE_SYSTEM_PROCESSOR}
    # ${CMAKE_CURRENT_BINARY_DIR}/third/libbpf
    ${CMAKE_CURRENT_SOURCE_DIR}/third/libbpf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/libbpf/include/uapi
)

# compile coolbpf library
add_subdirectory(src)
# test cases
add_subdirectory(tests)