include(${PROJECT_SOURCE_DIR}/scripts/cmake/genskel.cmake)

message(STATUS "net bpf INSTALL_INCLUDE_DIR: ${INSTALL_INCLUDE_DIR}")
genskel(net)