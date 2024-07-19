find_package(MPI REQUIRED)
add_executable(df_tracer_test test.cpp)
target_link_libraries(df_tracer_test MPI::MPI_CXX)