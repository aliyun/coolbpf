
include(${PROJECT_SOURCE_DIR}/scripts/cmake/genskel.cmake)

genskel(first)
genskel(second)

add_executable(mapreuse mapreuse.c)
target_include_directories(mapreuse PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(mapreuse first_skel second_skel)
target_link_libraries(mapreuse PRIVATE coolbpf)