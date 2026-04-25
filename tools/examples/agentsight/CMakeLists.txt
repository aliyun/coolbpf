# AgentSight C FFI example
# Links against libagentsight (Rust cdylib) — no BPF program needed.
# Only available when ENABLE_AGENTSIGHT is ON.

if(ENABLE_AGENTSIGHT)
    add_executable(agentsight_example agentsight_example.c)
    target_include_directories(agentsight_example PRIVATE
        ${CMAKE_SOURCE_DIR}/src/agentsight/include)
    add_dependencies(agentsight_example libagentsight)
    target_link_libraries(agentsight_example PRIVATE
        ${CMAKE_BINARY_DIR}/src/agentsight/release/libagentsight.so pthread)
    message(STATUS "AgentSight example enabled")
else()
    message(STATUS "AgentSight example disabled (set ENABLE_AGENTSIGHT=on to enable)")
endif()
