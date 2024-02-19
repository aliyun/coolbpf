
include(${PROJECT_SOURCE_DIR}/scripts/cmake/genskel.cmake)

genskel(asm)

add_executable(asm asm.c)
target_include_directories(asm PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(asm asm_skel)
target_link_libraries(asm PRIVATE coolbpf)