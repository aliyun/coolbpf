
add_library(helpers 
                errno_helpers.c 
                map_helpers.c
                syscall_helpers.c
                trace_helpers.c
                uprobe_helpers.c)

target_link_libraries(helpers libbpf)
