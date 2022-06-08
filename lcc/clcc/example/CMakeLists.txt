


add_custom_command(
    OUTPUT example.skel.h
    COMMAND sh make.sh ${CMAKE_CURRENT_SOURCE_DIR}/example.bpf.c ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/compile/local-compile
    COMMENT "Local Compile: example netinfo.skel.h"
)

add_executable(example example.c example.skel.h)
target_link_libraries(example libbpf helpers)
target_include_directories(example PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
