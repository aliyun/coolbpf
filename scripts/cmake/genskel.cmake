
include(${PROJECT_SOURCE_DIR}/scripts/cmake/arch.cmake)
message(STATUS "ARCH: ${ARCH}")

find_program(BPFTOOL NAMES bpftool)
message(STATUS "Found bpftool: ${BPFTOOL}")

find_program(CLANG NAMES clang)
message(STATUS "Found clang: ${CLANG}")

message(STATUS "Archicture: ${CMAKE_SYSTEM_PROCESSOR}")

# get all include directories and add '-I'
get_directory_property(dirs INCLUDE_DIRECTORIES)
set(include_dirs "")
foreach(dir ${dirs})
    list(APPEND include_dirs "-I${dir}")
endforeach()
message(STATUS "Include Directories: ${include_dirs}")

macro(genskel name)
    SET(BPF_C_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${name}.bpf.c)
    SET(BPF_O_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
    SET(BPF_S_FILE ${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h)

    add_custom_command(
        OUTPUT ${BPF_O_FILE}
        COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} -I${include_dirs} -c ${BPF_C_FILE} -o ${BPF_O_FILE}
        DEPENDS ${BPF_C_FILE}
        COMMENT "Generating BPF object: ${BPF_O_FILE}"
    )

    add_custom_command(
        OUTPUT ${BPF_S_FILE}
        COMMAND ${BPFTOOL} gen skeleton ${BPF_O_FILE} > ${BPF_S_FILE}
        DEPENDS ${BPF_O_FILE}
        COMMENT "Generating BPF skeleton: ${BPF_S_FILE}"
    )

    add_custom_target(
        ${name}_skel
        DEPENDS ${BPF_S_FILE}
    )
endmacro()

