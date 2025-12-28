add_library(l7_core_exception
    L7_Except.c
)

target_include_directories(l7_core_exception
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../../include>
    $<INSTALL_INTERFACE:include>
)
