add_library(l7_core_logger
  L7_Logger.c
)

target_include_directories(l7_core_logger
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../../include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(l7_core_logger
    PUBLIC l7_core_exception
)
