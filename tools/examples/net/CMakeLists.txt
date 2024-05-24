

add_executable(net net.c)
target_link_libraries(net PRIVATE coolbpf pthread dl)