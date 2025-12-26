/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#pragma once

#include <setjmp.h>

/**
 * @file L7_Except.h
 * @ingroup foundation
 * @brief Structured exception handling for C with L7_TRY/L7_EXCEPT/L7_FINALLY
 * blocks.
 *
 * Provides try/catch/finally semantics using setjmp/longjmp. Each thread
 * maintains an independent exception stack for concurrent operations.
 *
 * ## Usage
 *
 * @code{.c}
 * extern const L7_Except_T MyError;
 *
 * void example(void) {
 *   L7_TRY {
 *     if (failure) L7_RAISE(MyError);
 *   } L7_EXCEPT(MyError) {
 *     fprintf(stderr, "Error: %s\n", L7_Except_frame.exception->reason);
 *   } L7_FINALLY {
 *     cleanup();
 *   } L7_END_TRY;
 * }
 * @endcode
 *
 * @note Variables modified in L7_TRY blocks must be volatile to survive
 * longjmp.
 * @warning Avoid setjmp/longjmp in signal handlers.
 */

/**
 * @brief L7_Exception payload with type identifier and description.
 *
 * Define module exceptions as: `const L7_Except_T MyError = { &BaseType,
 * "reason" };`
 */
typedef struct L7_Except_T {
  const struct L7_Except_T
      *type;          /**< Exception type for matching in L7_EXCEPT */
  const char *reason; /**< Human-readable error description */
} L7_Except_T;

/**
 * @brief Stack frame for exception handling context.
 *
 * Managed by L7_TRY/L7_END_TRY macros. Access L7_Except_frame.exception in
 * handlers.
 */
typedef struct L7_Except_Frame L7_Except_Frame;
struct L7_Except_Frame {
  L7_Except_Frame *prev;        /**< Previous frame in stack */
  jmp_buf env;                  /**< setjmp/longjmp context */
  const char *file;             /**< Source file of L7_RAISE */
  int line;                     /**< Source line of L7_RAISE */
  const L7_Except_T *exception; /**< Raised exception */
};

/** L7_Exception handling states (internal use) */
enum {
  L7_Except_entered = 0, /**< L7_TRY block entered */
  L7_Except_raised,      /**< L7_Exception raised */
  L7_Except_handled,     /**< L7_Exception handled */
  L7_Except_finalized    /**< L7_FINALLY executed */
};

/** Thread-local exception stack head */
#ifdef _WIN32
extern __declspec(thread) L7_Except_Frame *L7_Except_stack;
#else
extern __thread L7_Except_Frame *L7_Except_stack;
#endif

/** Base exception for assertion failures */
extern const L7_Except_T Assert_Failed;

/**
 * @brief Raise an exception (internal - use L7_RAISE macro).
 *
 * Performs longjmp to nearest L7_TRY block. Does not return.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
extern _Noreturn void L7_Except_raise(const L7_Except_T *e, const char *file,
                                      int line);
#elif defined(__GNUC__) || defined(__clang__)
extern void L7_Except_raise(const L7_Except_T *e, const char *file, int line)
    __attribute__((noreturn));
#elif defined(_MSC_VER)
extern __declspec(noreturn) void L7_Except_raise(const L7_Except_T *e,
                                                 const char *file, int line);
#else
extern void L7_Except_raise(const L7_Except_T *e, const char *file, int line);
#endif

/** Raise exception with file/line info */
#define L7_RAISE(e) L7_Except_raise(&(e), __FILE__, __LINE__)

/** Re-raise current exception to outer handler */
#define L7_RERAISE                                                             \
  L7_Except_raise((const L7_Except_T *)L7_Except_frame.exception,              \
                  L7_Except_frame.file, L7_Except_frame.line)

/** Return from function, cleaning up exception stack */
#define RETURN                                                                 \
  switch (L7_Except_stack = ((L7_Except_Frame *)L7_Except_stack)->prev, 0)     \
  default:                                                                     \
    return

/* Internal: pop frame if entered normally */
#define L7_EXCEPT_POP_FRAME_IF_ENTERED                                         \
  if (L7_Except_flag == L7_Except_entered) {                                   \
    L7_Except_Frame *prev_frame = NULL;                                        \
    if (L7_Except_stack != NULL)                                               \
      prev_frame = L7_Except_stack->prev;                                      \
    L7_Except_stack = prev_frame;                                              \
  }

/**
 * @brief Begin exception handling block.
 *
 * Use volatile for variables modified in L7_TRY that are read after exception.
 */
#define L7_TRY                                                                 \
  do {                                                                         \
    volatile int L7_Except_flag;                                               \
    volatile L7_Except_Frame L7_Except_frame;                                  \
    jmp_buf *env_ptr = (jmp_buf *)&L7_Except_frame.env;                        \
    L7_Except_frame.prev = L7_Except_stack;                                    \
    L7_Except_frame.file = NULL;                                               \
    L7_Except_frame.line = 0;                                                  \
    L7_Except_frame.exception = NULL;                                          \
    L7_Except_stack = (L7_Except_Frame *)&L7_Except_frame;                     \
    L7_Except_flag = setjmp(*env_ptr);                                         \
    if (L7_Except_flag == L7_Except_entered) {

/** Catch specific exception type */
#define L7_EXCEPT(e)                                                           \
  L7_EXCEPT_POP_FRAME_IF_ENTERED                                               \
  }                                                                            \
  else if (L7_Except_frame.exception &&                                        \
           L7_Except_frame.exception->type == &(e)) {                          \
    L7_Except_flag = L7_Except_handled;

/** Catch any unhandled exception */
#define L7_ELSE                                                                \
  L7_EXCEPT_POP_FRAME_IF_ENTERED                                               \
  }                                                                            \
  else {                                                                       \
    L7_Except_flag = L7_Except_handled;

/** Cleanup block - always executes */
#define L7_FINALLY                                                             \
  L7_EXCEPT_POP_FRAME_IF_ENTERED                                               \
  }                                                                            \
  {                                                                            \
    if (L7_Except_flag == L7_Except_entered)                                   \
      L7_Except_flag = L7_Except_finalized;

/** End exception block, re-raise if unhandled */
#define L7_END_TRY                                                             \
  L7_EXCEPT_POP_FRAME_IF_ENTERED                                               \
  }                                                                            \
  if (L7_Except_flag == L7_Except_raised)                                      \
    L7_RERAISE;                                                                \
  }                                                                            \
  while (0)

