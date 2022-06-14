



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

# compile ringbuffer driver
add_custom_command(
    OUTPUT ringbuffer_source
    COMMAND cp -r ${CMAKE_CURRENT_SOURCE_DIR}/lib/ringbuffer ${CMAKE_CURRENT_BINARY_DIR}/lib
    COMMENT "Copy ringbuffer driver code"
)

add_custom_command(
    OUTPUT ringbuffer.ko
    COMMAND ${CMAKE_MAKE_PROGRAM}
    DEPENDS ringbuffer_source
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib/ringbuffer
    COMMENT "Compile ebpf driver: Generate ringbuffer.ko"
)
add_custom_target(ringbuffer DEPENDS ringbuffer.ko)

# compile hook
add_subdirectory(lib/hook)