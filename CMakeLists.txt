cmake_minimum_required(VERSION 3.4)
project(dfprofiler LANGUAGES C CXX)

set(DFT_EBPF_SRC src/dfprofiler/library.c src/dfprofiler/library.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(${PROJECT_NAME} SHARED ${DFT_EBPF_SRC})

add_subdirectory(tests)