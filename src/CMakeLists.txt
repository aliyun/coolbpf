set(VERSION 1.0.0)

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

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/coolbpf.pc.in
  ${CMAKE_CURRENT_BINARY_DIR}/coolbpf.pc
  @ONLY
)

if(NOT DEFINED INSTALL_LIB_DIR)
  set (INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
endif()

if(NOT DEFINED INSTALL_INCLUDE_DIR)
  set (INSTALL_INCLUDE_DIR ${CMAKE_INSTALL_PREFIX}/include)
endif()

file(GLOB sources ${PROJECT_SOURCE_DIR}/third/libbpf/src/*.c ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
# share library
add_library(coolbpf SHARED ${sources})
target_link_libraries(coolbpf PRIVATE ${ELF_LIBRARY} ${Z_LIBRARY} pthread)
set_target_properties(coolbpf PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION})
# static library
add_library(coolbpf_static STATIC ${sources})
target_link_libraries(coolbpf_static PRIVATE ${ELF_LIBRARY} ${Z_LIBRARY} pthread)
set_target_properties(coolbpf_static PROPERTIES OUTPUT_NAME "coolbpf")

install(TARGETS coolbpf LIBRARY DESTINATION ${INSTALL_LIB_DIR})
install(TARGETS coolbpf_static ARCHIVE DESTINATION ${INSTALL_LIB_DIR})

# install coolbpf headers
file(GLOB headers "*.h" )
install(FILES ${headers} DESTINATION ${INSTALL_INCLUDE_DIR}/coolbpf)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/coolbpf.pc DESTINATION ${INSTALL_LIB_DIR}/pkgconfig)

# install bpf headers
file(GLOB bpf_headers ${PROJECT_SOURCE_DIR}/third/libbpf/src/*.h)
install(FILES ${bpf_headers} DESTINATION ${INSTALL_INCLUDE_DIR}/coolbpf/bpf)

# install uapi headers
set(UAPI_DIR ${PROJECT_SOURCE_DIR}/third/libbpf/include/uapi/linux/)
file(GLOB uapi_headers ${UAPI_DIR}/bpf_common.h ${UAPI_DIR}/btf.h ${UAPI_DIR}/bpf.h)
install(FILES ${uapi_headers} DESTINATION ${INSTALL_INCLUDE_DIR}/coolbpf/linux)

# install vmlinux header
install(FILES ${PROJECT_SOURCE_DIR}/arch/${CMAKE_SYSTEM_PROCESSOR}/vmlinux.h DESTINATION ${INSTALL_INCLUDE_DIR}/coolbpf)