cmake_minimum_required(VERSION 3.19)
project(lbc C)

set(CMAKE_C_STANDARD 99)
include_directories(include bpf)
add_executable(bpf/lbc.bpf.c scr/bpf_init.c)
add_library(lbc)