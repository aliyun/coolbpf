set(CMAKE_INSTALL_PREFIX "/root/coolbpf/build/tmp")

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



file(GLOB sources ${PROJECT_SOURCE_DIR}/third/libbpf/src/*.c ${CMAKE_CURRENT_SOURCE_DIR}/*.c)

add_library(coolbpf STATIC SHARED ${sources})


install(TARGETS coolbpf
    LIBRARY DESTINATION lib
)

file(GLOB headers "*.h" )
install(FILES ${headers} DESTINATION include/coolbpf)