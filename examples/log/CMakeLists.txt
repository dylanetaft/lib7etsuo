cmake_minimum_required(VERSION 3.10)
project(lib7etsuo_examples_exceptions LANGUAGES C)
include(FetchContent)

FetchContent_Declare (
    lib7etsuo
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../"
)
FetchContent_MakeAvailable(lib7etsuo)

add_executable(example_1)
target_sources(example_1 PRIVATE example_1.c)
target_link_libraries(example_1 PRIVATE l7_core_logger)
