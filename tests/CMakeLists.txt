

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRITERION REQUIRED criterion)
LINK_DIRECTORIES(${CRITERION_LIBDIR})


add_subdirectory(bpf)

enable_testing()

add_executable(testapi testapi.c)
target_link_libraries(testapi PRIVATE coolbpf ${CRITERION_LIBRARIES} z elf)
add_test(testapi testapi)


add_executable(testbpf testbpf.c)
add_dependencies(testbpf test_skel test_map_skel)
target_include_directories(testbpf PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/bpf)
target_link_libraries(testbpf PRIVATE coolbpf ${CRITERION_LIBRARIES} z elf)
add_test(testbpf testbpf)

add_executable(bpf_core bpf_core.c)
add_dependencies(bpf_core bpf_core_skel)
target_include_directories(bpf_core PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/bpf)
target_link_libraries(bpf_core PRIVATE coolbpf ${CRITERION_LIBRARIES} z elf)
add_test(bpf_core bpf_core)

add_custom_target(test COMMAND ${CMAKE_CTEST_COMMAND}
                  DEPENDS testapi testbpf bpf_core)
