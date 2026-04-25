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
option(ENABLE_ASAN "Enable asan" OFF)
option(ENABLE_PROFILE "Enable profile" ON)
option(ENABLE_AGENTSIGHT "Build AgentSight library" OFF)
option(ENABLE_STATIC_LINK_ELF "Enable static link libelf" OFF)

IF (ENABLE_GCOV)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
ENDIF()

message(STATUS "coolbpf C compile flags: ${CMAKE_C_FLAGS}")

# compile coolbpf library
add_subdirectory(src)
# test cases
add_subdirectory(tests)

add_subdirectory(tools)

if(BUILD_LCC)
    add_subdirectory(lcc)
    add_subdirectory(third)
endif()
