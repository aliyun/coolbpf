

add_library(btfparse btfparse.c)
target_link_libraries(btfparse libbpf)
target_include_directories(btfparse PRIVATE ${CMAKE_CURRENT_BINARY_DIR})



add_executable(btfparsetest btfparsetest.c)
target_link_libraries(btfparsetest libbpf btfparse)