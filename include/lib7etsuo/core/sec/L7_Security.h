#pragma once

#include <stdint.h>

#ifndef L7_SEC_ARENA_MAX_ALLOCATION
#define L7_SEC_ARENA_MAX_ALLOCATION (256UL * 1024 * 1024) /**< 256 MB */ 
#endif


/**
 * @brief Validate addition of two sizes for potential overflow.
 *
 * @param a       First addend
 * @param b       Second addend
 * @param result  Optional pointer to store a + b if no overflow, or NULL
 *
 * Returns: 1 if addition safe (no overflow), 0 if would overflow
 *
 * @threadsafe Yes
 * @complexity O(1)
 */

static inline int L7_Sec_sz_check_add(size_t a, size_t b, size_t *result) {

  if (a > SIZE_MAX - b) {
      // Overflow would occur
      return 0;
  }

  if (result != NULL) {
        *result = a + b;
    }
    return 1; // No overflow
}



/**
 * @brief Compute product of two sizes with overflow protection (inline).
 *
 * @param a  First size_t operand
 * @param b  Second size_t operand
 *
 * Returns: Returns 1 if multiplication is safe , else 0
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
static inline int L7_Sec_sz_check_mul(size_t a, size_t b, size_t *result) {

  if (a == 0 || b == 0) {
      if (result != NULL) *result = 0; 
      return 1; // Multiplication by zero is safe
  }

  if (a > SIZE_MAX / b) {
      // Overflow would occur
      return 0;
  }

  if (result != NULL) *result = a * b; 
    return 1; // No overflow
} 

/**
 * @brief Check if size is within allowed maximum allocation limit.
 *
 * @param size  Size to check
 *
 * Returns: 1 if size is valid, else 0
 *
 * @threadsafe Yes
 * @complexity O(1)
 */
static inline int L7_Sec_sz_check_size(size_t size) {
  if (size == 0) return 0;
  if (size > L7_SEC_ARENA_MAX_ALLOCATION) return 0;
  if (size > SIZE_MAX / 2) /* Defense-in-depth against overflow */
    return 0;
  return 1;
}

