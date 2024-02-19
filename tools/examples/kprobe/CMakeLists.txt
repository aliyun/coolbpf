
include(${PROJECT_SOURCE_DIR}/scripts/cmake/genskel.cmake)

genskel(kprobe)

add_executable(kprobe kprobe.c)
target_include_directories(kprobe PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(kprobe kprobe_skel)
target_link_libraries(kprobe PRIVATE coolbpf)