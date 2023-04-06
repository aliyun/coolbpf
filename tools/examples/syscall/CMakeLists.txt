
include(${PROJECT_SOURCE_DIR}/scripts/cmake/genskel.cmake)

genskel(syscall)

add_executable(syscall syscall.c)
target_include_directories(syscall PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(syscall syscall_skel)
target_link_libraries(syscall PRIVATE coolbpf)