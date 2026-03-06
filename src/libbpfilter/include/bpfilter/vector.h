/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

/**
 * @file vector.h
 *
 * Dynamically-sized array of fixed-size elements, backed by a single
 * contiguous allocation. Elements are stored inline (not as pointers),
 * so the caller decides the element type and size at initialization.
 */

struct bf_vector;

#define _free_bf_vector_ __attribute__((cleanup(bf_vector_free)))
#define _clean_bf_vector_ __attribute__((cleanup(bf_vector_clean)))

/**
 * @struct bf_vector
 *
 * @var bf_vector::data
 *  Backing buffer. NULL when the vector is empty and has never been allocated.
 * @var bf_vector::len
 *  Number of elements currently stored.
 * @var bf_vector::cap
 *  Number of elements that can be stored before a reallocation is needed.
 * @var bf_vector::elem_size
 *  Size of a single element in bytes.
 */
struct bf_vector
{
    void *data;
    size_t len;
    size_t cap;
    size_t elem_size;
};

/**
 * Returns a zero-initialized @ref bf_vector for elements of size @p esz.
 *
 * @param esz Size of a single element in bytes.
 * @return A zero-initialized @ref bf_vector.
 */
#define bf_vector_default(esz)                                                 \
    (struct bf_vector)                                                         \
    {                                                                          \
        .data = NULL, .len = 0, .cap = 0, .elem_size = (esz)                   \
    }

/**
 * Iterate over every element of a @ref bf_vector.
 *
 * @p elem is declared as a pointer to the element type and will point to each
 * element in turn. Safe to break out of but not to remove elements during
 * iteration.
 *
 * @param vec Pointer to the vector. Must be non-NULL.
 * @param elem Name of the iteration variable. Will be declared as a
 *        `void *` and cast by the caller.
 */
#define bf_vector_foreach(vec, elem)                                           \
    for (void *(elem) = (vec)->data;                                           \
         (elem) && (elem) < (void *)((char *)(vec)->data +                     \
                                     (vec)->len * (vec)->elem_size);           \
         (elem) = (char *)(elem) + (vec)->elem_size)

/**
 * Allocate and initialise a new vector on the heap.
 *
 * @param vec Pointer to the vector pointer. Must be non-NULL. On failure,
 *        `*vec` is unchanged.
 * @param elem_size Size of a single element in bytes. Must be > 0.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_new(struct bf_vector **vec, size_t elem_size);

/**
 * Free a heap-allocated vector.
 *
 * @param vec Pointer to the vector pointer. Must be non-NULL.
 */
void bf_vector_free(struct bf_vector **vec);

/**
 * Clean up a vector, freeing its backing buffer.
 *
 * After this call the vector can be reused by calling @ref bf_vector_new
 * or discarded.
 *
 * @param vec Pointer to the vector. Must be non-NULL.
 */
void bf_vector_clean(struct bf_vector *vec);

/**
 * Get the number of elements in the vector.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Number of elements stored.
 */
size_t bf_vector_len(const struct bf_vector *vec);

/**
 * Get the current capacity.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Number of elements that fit without reallocation.
 */
size_t bf_vector_cap(const struct bf_vector *vec);

/**
 * Get a pointer to the n-th element.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param index Index of the element. Must be < @ref bf_vector_len.
 * @return Pointer to the element, or NULL if @p index is out of bounds.
 */
void *bf_vector_get(const struct bf_vector *vec, size_t index);

/**
 * Append an element to the end of the vector, growing it if necessary.
 *
 * The element is copied from @p elem into the vector's backing buffer.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param elem Pointer to the element to copy in. Must be non-NULL and point
 *        to at least @c vec->elem_size bytes.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_add(struct bf_vector *vec, const void *elem);

/**
 * Resize the vector's backing buffer to hold exactly @p new_cap elements.
 *
 * @p new_cap must be >= the current length. If @p new_cap is 0 the backing
 * buffer is freed.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param new_cap New capacity (in number of elements).
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_resize(struct bf_vector *vec, size_t new_cap);
