#pragma once
#include <lib7etsuo/core/except/L7_Except.h>
#include <string.h>

#ifndef L7_LOG_BUFSIZE
#define L7_LOG_BUFSIZE 1024
#endif

// Define thread_local for standards before C23
#if !defined(thread_local) &&                                                  \
    (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 202311L)
#define thread_local _Thread_local
#endif

#ifndef L7_LOG_TRUNCATION_MARKER
#define L7_LOG_TRUNCATION_MARKER "...truncated"
#endif

#define L7_LOG_TRUNCATION_MARKER_LEN (sizeof(L7_LOG_TRUNCATION_MARKER) - 1)

typedef enum L7LogLevel {
  L7_LOG_TRACE = 0,
  L7_LOG_DEBUG,
  L7_LOG_INFO,
  L7_LOG_WARN,
  L7_LOG_ERROR,
  L7_LOG_FATAL
} L7LogLevel;


void L7_Log_apply_truncation(char *b_in, size_t b_in_size, char *b_out,
                              size_t b_out_size);

void L7_Log_emit(L7LogLevel level, const char *component,
                 const char *message);

#define L7_DECLARE_MODULE_EXCEPTION(module_name)                               \
  static thread_local L7_Except_T module_name##_DetailedException

/**
 * @brief L7_RAISE_MODULE_ERROR - Raise module-specific exception

 * @module_name: Module name
 * @exception: Exception to raise
 * @brief Thread-safe: Creates thread-local copy with detailed reason

 */
#define L7_RAISE_MODULE_ERROR(module_name, exception)                          \
  do {                                                                         \
    module_name##_DetailedException = (exception);                             \
    module_name##_DetailedException.reason = error_buf;                        \
    RAISE(module_name##_DetailedException);                                    \
  } while (0)

/**
 * @brief L7_RAISE_MSG - Format error message and raise exception in one
 step

 * @module_name: Module name for exception
 * @exception: Exception to raise
 * @fmt: Printf-style format string (without errno)
 * @...: Format arguments
 *
 * Combines L7_ERROR_MSG + L7_RAISE_MODULE_ERROR into single macro.
 * @brief Thread-safe: Yes (uses thread-local buffers)

 */
#define L7_RAISE_MSG(module_name, exception, fmt, ...)                         \
  do {                                                                         \
    L7_ERROR_MSG(fmt, ##__VA_ARGS__);                                          \
    L7_RAISE_MODULE_ERROR(module_name, exception);                             \
  } while (0)

/**
 * @brief L7_LOG_MSG - Format message

 * Includes truncation protection for long messages.
 */
#define L7_LOG_MSG(level, component, fmt, ...)                                                 \
  do {                                                                         \
    char tmp_buf[L7_LOG_BUFSIZE];                                            \
    snprintf(tmp_buf, sizeof(tmp_buf), fmt, ##__VA_ARGS__);           \
    L7_Log_apply_truncation(tmp_buf, L7_LOG_BUFSIZE - 1, tmp_buf, L7_LOG_BUFSIZE);                              \
    L7_Log_emit(level, component, tmp_buf);                 \
  } while (0)
