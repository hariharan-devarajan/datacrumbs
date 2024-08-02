cmake_minimum_required(VERSION 3.4)
project(datacrumbs LANGUAGES C CXX)

set(DFT_EBPF_SRC src/datacrumbs/library.c src/datacrumbs/library.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(${PROJECT_NAME} SHARED ${DFT_EBPF_SRC})

add_subdirectory(tests)