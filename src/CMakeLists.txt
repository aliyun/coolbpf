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
add_library(coolbpf SHARED ${sources})
set_target_properties(coolbpf PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION})
install(TARGETS coolbpf LIBRARY DESTINATION ${INSTALL_LIB_DIR})

file(GLOB headers "*.h" )
install(FILES ${headers} DESTINATION ${INSTALL_INCLUDE_DIR}/coolbpf)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/coolbpf.pc DESTINATION ${INSTALL_LIB_DIR}/pkgconfig)