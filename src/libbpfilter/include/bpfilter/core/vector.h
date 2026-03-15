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

struct bf_vector
{
    /// Backing buffer. NULL when the vector is empty and has never been allocated.
    void *data;
    /// Number of elements currently stored.
    size_t len;
    /// Number of elements that can be stored before a reallocation is needed.
    size_t cap;
    /// Size of a single element in bytes.
    size_t elem_size;
};

/**
 * @brief Returns a zero-initialized `bf_vector` for elements of size `esz`.
 *
 * @param esz Size of a single element in bytes.
 * @return A zero-initialized `bf_vector`.
 */
#define bf_vector_default(esz)                                                 \
    (struct bf_vector)                                                         \
    {                                                                          \
        .data = NULL, .len = 0, .cap = 0, .elem_size = (esz)                   \
    }

/**
 * @brief Iterate over every element of a @ref bf_vector.
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
         (elem) && (elem) < (vec)->data + (vec)->len * (vec)->elem_size;       \
         (elem) = (elem) + (vec)->elem_size)

/**
 * @brief Allocate and initialise a new vector on the heap.
 *
 * @param vec Pointer to the vector pointer. Must be non-NULL. On failure,
 *        `*vec` is unchanged.
 * @param elem_size Size of a single element in bytes. Must be > 0.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_new(struct bf_vector **vec, size_t elem_size);

/**
 * @brief Free a heap-allocated vector.
 *
 * @param vec Pointer to the vector pointer. Must be non-NULL.
 */
void bf_vector_free(struct bf_vector **vec);

/**
 * @brief Clean up a vector, freeing its backing buffer.
 *
 * After this call the vector can be reused (e.g. by re-assigning via
 * @ref bf_vector_default) or discarded.
 *
 * @param vec Pointer to the vector. Must be non-NULL.
 */
void bf_vector_clean(struct bf_vector *vec);

/**
 * @brief Get the number of elements in the vector.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Number of elements stored.
 */
size_t bf_vector_len(const struct bf_vector *vec);

/**
 * @brief Get the current capacity.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Number of elements that fit without reallocation.
 */
size_t bf_vector_cap(const struct bf_vector *vec);

/**
 * @brief Get a pointer to the n-th element.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param index Index of the element. Must be < `bf_vector_len`.
 * @return Pointer to the element, or NULL if @p index is out of bounds.
 */
void *bf_vector_get(const struct bf_vector *vec, size_t index);

/**
 * @brief Append an element to the end of the vector, growing it if necessary.
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
 * @brief Resize the vector's backing buffer to hold exactly @p new_cap elements.
 *
 * @p new_cap must be >= the current length. If @p new_cap is 0 the backing
 * buffer is freed.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param new_cap New capacity (in number of elements).
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_vector_resize(struct bf_vector *vec, size_t new_cap);

/**
 * @brief Get a pointer to the backing buffer.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Pointer to the first byte, or NULL if the vector has never been
 *         allocated.
 */
void *bf_vector_data(const struct bf_vector *vec);

/**
 * @brief Take ownership of the backing buffer.
 *
 * Returns the raw data pointer and resets the vector so it will
 * re-allocate on the next add.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @return Pointer to the backing buffer, or NULL if it was never allocated.
 *         The caller is responsible for freeing this memory.
 */
void *bf_vector_take(struct bf_vector *vec);

/**
 * @brief Set the number of live elements.
 *
 * @p len must be <= the current capacity. No initialization of the new
 * elements is performed.
 *
 * @param vec Initialised vector. Must be non-NULL.
 * @param len New element count.
 * @return 0 on success, or -EINVAL if @p len exceeds the capacity.
 */
int bf_vector_set_len(struct bf_vector *vec, size_t len);
