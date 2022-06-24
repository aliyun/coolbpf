


add_custom_command(
    OUTPUT output
    COMMAND mkdir -p .output
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/
    COMMENT "Create .output directory"
)

add_custom_command(
    OUTPUT example.bpf.o
    COMMAND coolbpf -f example.bpf.c -o
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/
    COMMENT "Remote Compile: Generate example.bpf.o"
)

add_custom_command(
    OUTPUT example.skel.rs
    COMMAND ${PROJECT_SOURCE_DIR}/lcc/rlcc/tools/cargo-libbpf libbpf gen --object ../example.bpf.o > example.skel.rs
    DEPENDS output example.bpf.o
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf/.output
    COMMENT "Local Compile: Generate example.skel.rs"
)

add_custom_command(
    OUTPUT rexample_target
    COMMAND cargo build --release
    DEPENDS example.skel.rs
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Local Compile: Generate rexample binary program"
)

add_custom_target(rexample DEPENDS rexample_target)