project(coolbpf C)
cmake_minimum_required(VERSION 2.8.12)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}/third
    ${CMAKE_CURRENT_SOURCE_DIR}/arch/${CMAKE_SYSTEM_PROCESSOR}
    # ${CMAKE_CURRENT_BINARY_DIR}/third/libbpf
    ${CMAKE_CURRENT_SOURCE_DIR}/third/libbpf/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third/libbpf/include/uapi
)


option(BUILD_TESTING "Build test cases" OFF)
option(BUILD_EXAMPLE "Build example cases" OFF)
option(BUILD_LCC "Build lcc project" OFF)
OPTION(ENABLE_GCOV "Enable gcov" OFF)

IF (ENABLE_GCOV)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
ENDIF()

# compile coolbpf library
add_subdirectory(src)
# test cases
add_subdirectory(tests)

add_subdirectory(tools)

if(BUILD_LCC)
    add_subdirectory(lcc)
    add_subdirectory(third)
endif()