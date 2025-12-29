/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2025 Tetsuo AI
 * https://x.com/tetsuoai
 */

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <lib7etsuo/core/mem/L7_Arena.h>
#include <lib7etsuo/core/except/L7_Except.h>
#include <lib7etsuo/core/sec/L7_MemSafety.h>
#define T L7_Arena_T

struct ChunkHeader
{
  struct ChunkHeader *prev;
  char *avail;
  char *limit;
  size_t chunk_size;
};

union header
{
  struct ChunkHeader b;
  /* cppcheck-suppress unusedStructMember */
  union T7_align a;
};

struct T
{
  struct ChunkHeader *prev;
  char *avail;
  char *limit;
  pthread_mutex_t mutex;
  int locked; /* 0 = unlocked (TLS), 1 = locked (normal) */
};

static inline size_t
chunk_total_size (const struct ChunkHeader *chunk)
{
  return sizeof (union header) + chunk->chunk_size;
}

static inline char *
chunk_limit (const struct ChunkHeader *chunk)
{
  return (char *)chunk + chunk_total_size (chunk);
}

/* Link new chunk into arena's allocation chain (must hold arena->mutex) */
static inline void
arena_link_chunk (T arena, struct ChunkHeader *ptr, char *limit)
{

  ptr->prev = arena->prev;
  ptr->avail = arena->avail;
  ptr->limit = arena->limit;

  arena->avail = (char *)((union header *)ptr + 1);
  arena->limit = limit;
  arena->prev = ptr;
}

const L7_Except_T Arena_Failed = { &Arena_Failed, "Arena operation failed" };

L7_DECLARE_MODULE_EXCEPTION (Arena);

static struct ChunkHeader *freechunks = NULL;
static int nfree = 0;
static pthread_mutex_t arena_mutex = PTHREAD_MUTEX_INITIALIZER;

static _Atomic size_t global_memory_used = 0;
static _Atomic size_t global_memory_limit = 0; /* 0 = unlimited */

static int check_alloc_allowed (size_t current, size_t nbytes, size_t limit);

static int
global_memory_try_unlimited (size_t nbytes)
{
  atomic_fetch_add_explicit (&global_memory_used, nbytes,
                             memory_order_relaxed);
  return 1;
}

/* Allocate under limited policy with atomic CAS to prevent TOCTOU races */
static int
global_memory_try_limited (size_t limit, size_t nbytes)
{
  size_t current
      = atomic_load_explicit (&global_memory_used, memory_order_acquire);
  size_t desired;

  do
    {
      if (!check_alloc_allowed (current, nbytes, limit))
        return 0;

      desired = current + nbytes;
    }
  while (!atomic_compare_exchange_weak_explicit (&global_memory_used, &current,
                                                 desired, memory_order_acq_rel,
                                                 memory_order_acquire));

  return 1;
}

static int
global_memory_try_alloc (size_t nbytes)
{
  size_t limit
      = atomic_load_explicit (&global_memory_limit, memory_order_acquire);

  if (limit == 0)
    return global_memory_try_unlimited (nbytes);

  return global_memory_try_limited (limit, nbytes);
}

static void
global_memory_release (size_t nbytes)
{
  atomic_fetch_sub_explicit (&global_memory_used, nbytes,
                             memory_order_relaxed);
}

static int
check_alloc_allowed (size_t current, size_t nbytes, size_t limit)
{
  size_t desired;
  if (!L7_sec_sz_check_add (current, nbytes, &desired))
    return 0;

  if (limit > 0 && desired > limit)
    return 0;

  return 1;
}

#define ARENA_VALID_PTR_ARITH(ptr, offset, max)                               \
  (((uintptr_t)(ptr) <= UINTPTR_MAX - (offset))                               \
   && ((uintptr_t)(ptr) + (offset) <= (uintptr_t)(max)))

static int
validate_chunk_size (size_t chunk_size, size_t *total_out)
{
  size_t total;

  if (!L7_sec_sz_check_add (sizeof (union header), chunk_size, &total))
    {
      L7_LOG_MSG_TRUSTED(L7_LOG_ERROR, "Arena",
          "Chunk size overflow: sizeof(header)=%zu + chunk_size=%zu",
          sizeof (union header), chunk_size);
      return L7_ARENA_FAILURE;
    }

  if (!L7_sec_sz_check_size(total))
    {
      L7_LOG_MSG_TRUSTED (L7_LOG_ERROR, "ArenA", "Chunk size exceeds maximum: %zu (limit=%zu)", total,
                        L7_SEC_ARENA_MAX_ALLOCATION);
      return L7_ARENA_FAILURE;
    }

  *total_out = total;
  return L7_ARENA_SUCCESS;
}

static int
acquire_global_memory (size_t total)
{
  if (!global_memory_try_alloc (total))
    {
      fprintf(stderr, "TODO: Put metric counting here\n");
      return L7_ARENA_FAILURE;
    }

  return L7_ARENA_SUCCESS;
}

static struct ChunkHeader *
allocate_raw_chunk (size_t total)
{
  struct ChunkHeader *ptr = malloc (total);
  if (ptr == NULL)
    {
      global_memory_release (total);
      fprintf(stderr, "Cannot allocate chunk: %zu bytes\n", total);
      return NULL;
    }

  /* Validate pointer arithmetic won't overflow */
  if (!ARENA_VALID_PTR_ARITH (ptr, total, (void *)UINTPTR_MAX))
    {
      free (ptr);
      global_memory_release (total);
      fprintf(stderr, "Invalid pointer arithmetic for chunk\n");
      return NULL;
    }

  return ptr;
}

static int
chunk_cache_get (struct ChunkHeader **ptr_out, char **limit_out)
{
  int result = L7_ARENA_CHUNK_NOT_REUSED;

  pthread_mutex_lock (&arena_mutex);

  if (freechunks != NULL)
    {
      *ptr_out = freechunks;
      freechunks = freechunks->prev;
      nfree--;
      *limit_out = chunk_limit (*ptr_out);
      result = L7_ARENA_CHUNK_REUSED;
    }

  pthread_mutex_unlock (&arena_mutex);

  return result;
}

static void
chunk_cache_return (struct ChunkHeader *chunk)
{
  int added = 0;

  assert (chunk);

  pthread_mutex_lock (&arena_mutex);

  if (nfree < L7_ARENA_MAX_FREE_CHUNKS)
    {
      chunk->prev = freechunks;
      freechunks = chunk;
      nfree++;
      added = 1;
    }

  pthread_mutex_unlock (&arena_mutex);

  if (!added)
    {
      size_t total_bytes = chunk_total_size (chunk);
      free (chunk);
      global_memory_release (total_bytes);
    }
}

static size_t
arena_align_size (size_t nbytes)
{
  size_t align = L7_ARENA_ALIGNMENT_SIZE;
  size_t sum;
  size_t units;
  size_t final_size;
  // Subtracting 1 from align makes division round up
  if (!L7_sec_sz_check_add (nbytes, align - 1, &sum)) { 
    L7_LOG_MSG_TRUSTED (L7_LOG_ERROR, "Arena",
                        "Size alignment overflow: nbytes=%zu + align-1=%zu",
                        nbytes, align - 1);
    return 0;
  }

  units = sum / align;

  if (!L7_sec_sz_check_mult (units, align, &final_size)) {
    L7_LOG_MSG_TRUSTED (L7_LOG_ERROR, "Arena",
                        "Size alignment multiplication overflow: units=%zu * "
                        "align=%zu",
                        units, align);
    return 0;
  }

  return final_size;
}

static size_t
arena_calculate_aligned_size (size_t nbytes)
{
  size_t final_size;

  if (!L7_sec_sz_check_size (nbytes))
    return 0;
  L7_LOG_MSG_TRUSTED (L7_LOG_DEBUG, "Arena",
                      "Calculating aligned size for %zu bytes", nbytes);
  final_size = arena_align_size (nbytes);
  L7_LOG_MSG_TRUSTED (L7_LOG_DEBUG, "Arena",
                      "Aligned size: %zu bytes", final_size);

  /* Defensive check for rounding overflow (possible if align large relative to
   * max) */
  if (!L7_sec_sz_check_size (final_size))
    return 0;
  L7_LOG_MSG_TRUSTED (L7_LOG_DEBUG, "Arena",
                      "Final aligned size validated: %zu bytes", final_size);
  return final_size;
}

static int
arena_allocate_new_chunk (size_t chunk_size, struct ChunkHeader **ptr_out,
                          char **limit_out)
{
  size_t total;
  struct ChunkHeader *ptr;

  if (validate_chunk_size (chunk_size, &total) != L7_ARENA_SUCCESS)
    return L7_ARENA_FAILURE;

  if (acquire_global_memory (total) != L7_ARENA_SUCCESS)
    return L7_ARENA_FAILURE;

  ptr = allocate_raw_chunk (total);
  if (ptr == NULL)
    return L7_ARENA_FAILURE;

  ptr->chunk_size = chunk_size;
  *ptr_out = ptr;
  *limit_out = chunk_limit (ptr);

  return L7_ARENA_SUCCESS;
}

/* Must hold arena->mutex */
static int
arena_get_chunk (T arena, size_t min_size)
{
  struct ChunkHeader *ptr;
  char *limit;
  size_t chunk_size;

  if (chunk_cache_get (&ptr, &limit) == L7_ARENA_CHUNK_REUSED)
    {
      arena_link_chunk (arena, ptr, limit);
      return L7_ARENA_SUCCESS;
    }

  chunk_size = (L7_ARENA_CHUNK_SIZE < min_size) ? min_size : L7_ARENA_CHUNK_SIZE;

  if (arena_allocate_new_chunk (chunk_size, &ptr, &limit) != L7_ARENA_SUCCESS)
    return L7_ARENA_FAILURE;

  arena_link_chunk (arena, ptr, limit);
  return L7_ARENA_SUCCESS;
}

/* Must hold arena->mutex */
static void
arena_release_all_chunks (T arena)
{
  while (arena->prev != NULL)
    {
      struct ChunkHeader *chunk = arena->prev;
      struct ChunkHeader saved = *chunk;

      arena->prev = saved.prev;
      arena->avail = saved.avail;
      arena->limit = saved.limit;

      chunk_cache_return (chunk);
    }

  assert (arena->prev == NULL);
  assert (arena->avail == NULL);
  assert (arena->limit == NULL);
}

T
L7_Arena_new (void)
{
  T arena;

  arena = malloc (sizeof (struct T));
  if (arena == NULL)
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                      "Out of Memory: Cannot allocate arena structure");

  if (pthread_mutex_init (&arena->mutex, NULL) != 0)
    {
      free (arena);
      L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                        "Failed to initialize arena mutex");
    }

  arena->prev = NULL;
  arena->avail = NULL;
  arena->limit = NULL;
  arena->locked = 1;

  return arena;
}

T
L7_Arena_new_unlocked (void)
{
  T arena;

  arena = malloc (sizeof (struct T));
  if (arena == NULL)
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                      "Out of Memory: Cannot allocate arena structure");

  /* No mutex initialization for unlocked arenas */
  arena->prev = NULL;
  arena->avail = NULL;
  arena->limit = NULL;
  arena->locked = 0;

  return arena;
}


void
L7_Arena_dispose (T *ap)
{
  T arena;
  int locked;

  if (!ap || !*ap)
    return;

  /* Save arena pointer and locked flag before clearing, because ap itself
   * may point into memory allocated from this arena (e.g., if ap points to
   * a field within a structure that was arena-allocated). After Arena_clear
   * frees all chunks, dereferencing ap would be use-after-free. */
  arena = *ap;
  locked = arena->locked;

  L7_Arena_clear (arena);
  if (locked)
    pthread_mutex_destroy (&arena->mutex);
  free (arena);
  *ap = NULL;
}

void *
L7_Arena_alloc (T arena, size_t nbytes, const char *file, int line)
{
  (void)file;
  (void)line;
  if (arena == NULL)
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed, "NULL arena pointer in %s",
                      "Arena_alloc");

  if (nbytes == 0)
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                      "Zero size allocation in Arena_alloc");

  size_t aligned_size = arena_calculate_aligned_size (nbytes);
  if (aligned_size == 0)
    L7_RAISE_MSG_TRUSTED (
        Arena, Arena_Failed,
        "Invalid allocation size: %zu bytes (overflow or exceeds limit)",
        nbytes);

  if (arena->locked)
    pthread_mutex_lock (&arena->mutex);

  while (arena->avail == NULL || arena->limit == NULL
         || (size_t)(arena->limit - arena->avail) < aligned_size)
    {

      if (arena_get_chunk (arena, aligned_size) != L7_ARENA_SUCCESS)
        {
          if (arena->locked)
            pthread_mutex_unlock (&arena->mutex);
          L7_RAISE_MSG_TRUSTED (
              Arena, Arena_Failed,
              "Failed to allocate chunk for %zu bytes (out of memory)",
              aligned_size);
        }
    }
  void *result = arena->avail;
  arena->avail += aligned_size;

  if (arena->locked)
    pthread_mutex_unlock (&arena->mutex);

  return result;
}

void *
L7_Arena_calloc (T arena, size_t count, size_t nbytes, const char *file, int line)
{
  (void)file;
  (void)line;
  if (arena == NULL)
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed, "NULL arena pointer in %s",
                      "Arena_calloc");
  if (count == 0 || nbytes == 0)
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                      "Invalid count (%zu) or nbytes (%zu) in %s", count,
                      nbytes, "Arena_calloc");

  size_t total;
  if (!L7_sec_sz_check_mult (count, nbytes, &total))
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                      "calloc overflow: count=%zu, nbytes=%zu in %s", count,
                      nbytes, "Arena_calloc");

  if (!L7_sec_sz_check_size (total))
    L7_RAISE_MSG_TRUSTED (Arena, Arena_Failed,
                      "calloc size exceeds maximum: %zu (limit=%zu) in %s",
                      total, L7_SEC_ARENA_MAX_ALLOCATION,
                      "Arena_calloc");

  void *ptr = L7_Arena_alloc (arena, count * nbytes, file, line);
  memset (ptr, 0, count * nbytes);

  return ptr;
}

void
L7_Arena_clear (T arena)
{
  if (arena == NULL)
    return;

  if (arena->locked)
    pthread_mutex_lock (&arena->mutex);
  arena_release_all_chunks (arena);
  if (arena->locked)
    pthread_mutex_unlock (&arena->mutex);
}

void
L7_Arena_reset (T arena)
{
  struct ChunkHeader *first_chunk;
  struct ChunkHeader *chunk;

  if (arena == NULL)
    return;

  if (arena->locked)
    pthread_mutex_lock (&arena->mutex);

  /* Find the first (oldest) chunk by walking the prev chain */
  first_chunk = arena->prev;
  if (first_chunk == NULL)
    {
      /* No chunks allocated yet - nothing to reset */
      if (arena->locked)
        pthread_mutex_unlock (&arena->mutex);
      return;
    }

  /* Walk to find the first chunk (where saved.prev == NULL) */
  while (first_chunk->prev != NULL)
    first_chunk = first_chunk->prev;

  /* Release all chunks except the first one to the global cache.
   * Start from the current chunk and work backwards. */
  chunk = arena->prev;
  while (chunk != first_chunk)
    {
      struct ChunkHeader *prev_chunk = chunk->prev;
      chunk_cache_return (chunk);
      chunk = prev_chunk;
    }

  /* Reset arena to use just the first chunk from the beginning.
   * The first chunk's saved state has the original arena state (all NULL). */
  arena->prev = first_chunk;
  arena->avail = (char *)((union header *)first_chunk + 1);
  arena->limit = chunk_limit (first_chunk);

  if (arena->locked)
    pthread_mutex_unlock (&arena->mutex);
}

#undef T
