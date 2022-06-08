

find_library(ELF_LIBRARY
    NAMES elf
    PATHS /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64 ~/usr/local/lib ~/usr/local/lib64
)

find_library(Z_LIBRARY
    NAMES z
    PATHS /usr/lib /usr/local/lib /usr/lib64 /usr/local/lib64 ~/usr/local/lib ~/usr/local/lib64
)

if (ELF_LIBRARY)
    message("Found libelf library: ${ELF_LIBRARY}")
else (ELF_LIBRARY)
    message("Not found libelf library: ${ELF_LIBRARY}")
endif(ELF_LIBRARY)

add_custom_command(
		OUTPUT libbpf_header.h
        COMMAND ${CMAKE_MAKE_PROGRAM} install_headers INCLUDEDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
        COMMENT "install libbpf headers")
    
add_custom_command(
        OUTPUT vmlinux.h
        COMMAND ln -s ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux_515.h vmlinux.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "install vmlinux headers")

# compile libbpf
file(GLOB libbpf_sources "libbpf/src/*.c")
add_library(libbpf STATIC ${libbpf_sources} libbpf_header.h vmlinux.h)
# set_property(TARGET libbpf PROPERTY POSITION_INDEPENDENT_CODE 1)
target_include_directories(libbpf PRIVATE
			   ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include
			   ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/uapi)
target_link_libraries(libbpf ${ELF_LIBRARY} ${Z_LIBRARY})