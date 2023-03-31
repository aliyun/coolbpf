

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRITERION REQUIRED criterion)
LINK_DIRECTORIES(${CRITERION_LIBDIR})

enable_testing()

add_executable(testapi testapi.c)
target_link_libraries(testapi PRIVATE coolbpf ${CRITERION_LIBRARIES} z elf)
add_test(testapi testapi)


add_custom_target(test COMMAND ${CMAKE_CTEST_COMMAND}
                  DEPENDS testapi)