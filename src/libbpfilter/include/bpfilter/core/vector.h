/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

/**
 * @file vector.h
 *
 * Dynamically-sized array of fixed-size elements, backed by a single
 * contiguous allocation. Elements are stored inline (not as pointers),
 * so the caller decides the element type and size at initialization.
 * It automatically grows (by 1.5x), but never shrinks.
 */

typedef struct bf_vector
{
    /// Backing buffer. NULL when the vector is empty and has
    /// never been allocated.
    void *data;
    /// Number of elements currently stored.
    size_t size;
    /// Number of elements that can be stored before a reallocation is needed.
    size_t cap;
    /// Size of a single element in bytes.
    size_t elem_size;
} bf_vector;

#define _free_bf_vector_ __attribute__((cleanup(bf_vector_free)))
#define _clean_bf_vector_ __attribute__((cleanup(bf_vector_clean)))

/**
 * @brief Returns a zero-initialized `bf_vector` for elements of size
 *        `elem_size`.
 *
 * @param elem_size Size of a single element in bytes. Must be > 0.
 * @return A zero-initialized `bf_vector`.
 */
bf_vector bf_vector_default(size_t elem_size);

/**
 * @brief Initialise a stack-allocated vector for elements of size `elem_size`.
 *
 * @param vec Pointer to the vector. Must be non-NULL.
 * @param elem_size Size of a single element in bytes. Must be > 0.
 */
void bf_vector_init(bf_vector *vec, size_t elem_size);

/**
 * @brief Iterate over every element of a `bf_vector`.
 *
 * `elem` is declared as a pointer to the element type and will point to each
 * element in turn. Do not add or remove elements during iteration.
 *
 * @param vec Pointer to the vector. Must be non-NULL.
 * @param elem Name of the iteration variable. Will be declared as a
 *        `void *` and cast by the caller.
 */
#define bf_vector_foreach(vec, elem)                                           \
    for (void *(elem) = (vec)->data,                                           \
              *__end = (vec)->data ?                                           \
                           (char *)(vec)->data +                               \
                               ((vec)->size * (vec)->elem_size) :              \
                           NULL;                                               \
         (elem) && (elem) < __end;                                             \
         (elem) = (char *)(elem) + (vec)->elem_size)

/**
 * @brief Allocate and initialise a new vector on the heap.
 *
 * @param vec Pointer to the vector pointer. Must be non-NULL. On failure,
 *        `*vec` is unchanged.
 * @param elem_size Size of a single element in bytes. Must be > 0.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_new(bf_vector **vec, size_t elem_size);

/**
 * @brief Free a heap-allocated vector.
 *
 * @param vec Pointer to the vector pointer. Must be non-NULL.
 */
void bf_vector_free(bf_vector **vec);

/**
 * @brief Clean up a vector, freeing its backing buffer.
 *
 * After this call the vector can be reused (e.g. by re-assigning via
 * `bf_vector_default`) or discarded.
 *
 * @param vec Pointer to the vector. Must be non-NULL.
 */
void bf_vector_clean(bf_vector *vec);

/**
 * @brief Get a pointer to the n-th element.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param index Index of the element.
 * @return Pointer to the element, or NULL if `index` is out of bounds.
 */
void *bf_vector_get(const bf_vector *vec, size_t index);

/**
 * @brief Replace the n-th element.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param index Index of the element.
 * @param elem Pointer to the new value. Must be non-NULL and point to at
 *        least `vec->elem_size` bytes.
 * @return 0 on success, or -EINVAL if `index` is out of bounds.
 */
int bf_vector_set(bf_vector *vec, size_t index, const void *elem);

/**
 * @brief Remove the element at `index`, shifting subsequent elements left.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param index Index of the element to remove.
 * @return 0 on success, or -EINVAL if `index` is out of bounds.
 */
int bf_vector_remove(bf_vector *vec, size_t index);

/**
 * @brief Append an element to the end of the vector, growing it if necessary.
 *
 * The element is copied from `elem` into the vector's backing buffer.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param elem Pointer to the element to copy in. Must be non-NULL and point
 *        to at least `vec->elem_size` bytes.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_add(bf_vector *vec, const void *elem);

/**
 * @brief Append multiple elements to the end of the vector.
 *
 * Copies `count` elements (each `vec->elem_size` bytes) from `data` into
 * the vector, growing the backing buffer if necessary.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param data Pointer to the elements to copy in. Must be non-NULL and point
 *        to at least `count * vec->elem_size` bytes. Must not overlap with
 *        the vector's current contents.
 * @param count Number of elements to append. If 0, this is a no-op.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_add_many(bf_vector *vec, const void *data, size_t count);

/**
 * @brief Ensure the vector has capacity for at least `cap` elements.
 *
 * If the current capacity is already >= `cap`, this is a no-op.
 * Does not change the length or initialise any memory.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param cap Minimum number of elements the vector should be able to hold.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_reserve(bf_vector *vec, size_t cap);

/**
 * @brief Take ownership of the backing buffer.
 *
 * Returns the raw data pointer and resets the vector so it will
 * re-allocate on the next `bf_vector_add()`.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Pointer to the backing buffer, or NULL if it was never allocated.
 *         The caller is responsible for freeing this memory.
 */
void *bf_vector_take(bf_vector *vec);
