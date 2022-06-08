



# compile ebpf driver
add_custom_command(
    OUTPUT ebpfdrv_source
    COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/lib/ebpf ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMENT "Copy ebpf driver code"
)

add_custom_command(
    OUTPUT ebpfdrv.ko
    COMMAND ${CMAKE_MAKE_PROGRAM}
    DEPENDS ebpfdrv_source
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib/ebpf
    COMMENT "Compile ebpf driver: Generate ebpfdrv.ko"
)

add_custom_target(ebpfdrv DEPENDS ebpfdrv.ko)

# compile hook
add_subdirectory(lib/hook)