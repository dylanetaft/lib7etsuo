cmake_minimum_required(VERSION 3.10)
project(lib7etsuo_examples_exceptions LANGUAGES C)
include(FetchContent)

FetchContent_Declare (
    l7_util_exception
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../src/util/except"
)
FetchContent_MakeAvailable(l7_util_exception)

add_executable(example_1)
target_sources(example_1 PRIVATE example_1.c)
target_link_libraries(example_1 PRIVATE l7_util_exception)
