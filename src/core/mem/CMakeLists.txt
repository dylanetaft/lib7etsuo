add_library(l7_core_mem
    L7_Arena.c
)

target_include_directories(l7_core_mem
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../../include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(l7_core_mem
    PUBLIC l7_core_exception l7_core_logger
)

