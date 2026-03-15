/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/core/vector.h>

/**
 * @file hashset.h
 *
 * Open-addressing hashset with linear probing, backed by @ref bf_vector.
 * Each slot is a @c void* pointer. @c NULL means empty, sentinel value 1
 * means tombstone, anything else is a live element. Uses user-provided
 * callbacks (with an opaque context pointer) for hashing, comparison, and
 * cleanup.
 */

typedef uint64_t (*bf_hashset_ops_hash)(const void *data, void *ctx);
typedef bool (*bf_hashset_ops_equal)(const void *lhs, const void *rhs,
                                     void *ctx);
typedef void (*bf_hashset_ops_free)(void **data, void *ctx);

/**
 * @struct bf_hashset_ops
 *
 * @var bf_hashset_ops::hash
 *  Hash function for an element. Must be non-NULL.
 * @var bf_hashset_ops::equal
 *  Equality comparison for two elements. Must be non-NULL.
 * @var bf_hashset_ops::free
 *  Free callback for an element. If NULL, elements won't be freed.
 */
typedef struct
{
    bf_hashset_ops_hash hash;
    bf_hashset_ops_equal equal;
    bf_hashset_ops_free free;
} bf_hashset_ops;

/**
 * @struct bf_hashset
 *
 * @var bf_hashset::slots
 *  Backing vector of @c void* pointers.
 * @var bf_hashset::len
 *  Number of occupied slots (not counting tombstones).
 * @var bf_hashset::n_used
 *  Number of occupied + tombstone slots (used for load factor).
 * @var bf_hashset::ops
 *  Callbacks for hashing, comparing, and freeing elements.
 * @var bf_hashset::ctx
 *  Opaque context pointer passed to every callback.
 */
typedef struct bf_hashset
{
    struct bf_vector slots;
    size_t len;
    size_t n_used;
    bf_hashset_ops ops;
    void *ctx;
} bf_hashset;

#define _free_bf_hashset_ __attribute__((cleanup(bf_hashset_free)))
#define _clean_bf_hashset_ __attribute__((cleanup(bf_hashset_clean)))

/**
 * @brief Iterate over all occupied elements in a hashset.
 *
 * @param set Pointer to the hashset. Must be non-NULL.
 * @param elem_var Name of the @c void* variable to hold each element.
 */
#define bf_hashset_foreach(set, elem_var)                                      \
    for (size_t _bf_hset_brk = 0; !_bf_hset_brk; _bf_hset_brk = 1)            \
        bf_vector_foreach (&(set)->slots, _bf_hset_slot)                       \
            if (_bf_hset_brk || !(*(void **)_bf_hset_slot) ||                  \
                *(void **)_bf_hset_slot == (void *)1)                          \
                continue;                                                      \
            else                                                               \
                for (void *(elem_var) = (_bf_hset_brk = 1,                     \
                          *(void **)_bf_hset_slot);                            \
                     _bf_hset_brk; _bf_hset_brk = 0)

/**
 * @brief Allocate and initialise a new hashset.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param ops Callbacks for hashing, comparing, and freeing elements.
 *        @c hash and @c equal must be non-NULL. Can't be NULL.
 * @param ctx Opaque context pointer passed to every callback. Can be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_new(bf_hashset **set, const bf_hashset_ops *ops, void *ctx);

/**
 * @brief Free a hashset.
 *
 * @param set Pointer to the hashset pointer. Must be non-NULL.
 */
void bf_hashset_free(bf_hashset **set);

/**
 * @brief Initialise a stack-allocated hashset.
 *
 * @param set Set to initialise. Can't be NULL.
 * @param ops Callbacks for hashing, comparing, and freeing elements.
 *        @c hash and @c equal must be non-NULL. Can't be NULL.
 * @param ctx Opaque context pointer passed to every callback. Can be NULL.
 */
void bf_hashset_init(bf_hashset *set, const bf_hashset_ops *ops, void *ctx);

/**
 * @brief Clean up a hashset, freeing all elements and the backing buffer.
 *
 * After this call the hashset is empty and can be reused or discarded.
 *
 * @param set Pointer to the hashset. Must be non-NULL.
 */
void bf_hashset_clean(bf_hashset *set);

/**
 * @brief Get the number of elements in the hashset.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return Number of elements stored.
 */
static inline size_t bf_hashset_size(const bf_hashset *set)
{
    assert(set);
    return set->len;
}

/**
 * @brief Get the current number of slots.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return Current slot count.
 */
static inline size_t bf_hashset_cap(const bf_hashset *set)
{
    assert(set);
    return bf_vector_len(&set->slots);
}

/**
 * @brief Check if the hashset is empty.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return True if the hashset has no elements.
 */
static inline bool bf_hashset_is_empty(const bf_hashset *set)
{
    assert(set);
    return set->len == 0;
}

/**
 * @brief Insert an element into the hashset.
 *
 * If the element already exists, no duplicate is added and @c -EEXIST is
 * returned; ownership of @p data is **not** transferred in that case.
 * The hashset grows automatically when the load factor is exceeded.
 * On successful insertion, the hashset takes ownership of @p data.
 *
 * @param set Initialised hashset. Can't be NULL.
 * @param data Pointer to store. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_add(bf_hashset *set, void *data);

/**
 * @brief Check whether an element exists in the hashset.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param data Element to look up. Must be non-NULL.
 * @return True if a matching element is present.
 */
bool bf_hashset_contains(const bf_hashset *set, const void *data);

/**
 * @brief Look up an element in the hashset.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param data Element to search for. Must be non-NULL.
 * @return Pointer to the stored element, or NULL if not found.
 */
void *bf_hashset_get(const bf_hashset *set, const void *data);

/**
 * @brief Remove an element from the hashset.
 *
 * The slot is marked as a tombstone. The element is freed using the
 * @c free callback if one was provided. Removing an element that doesn't
 * exist is a no-op (returns 0).
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param data Element to remove. Must be non-NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_remove(bf_hashset *set, const void *data);

/**
 * @brief Take ownership of the hashset's backing storage.
 *
 * Returns the internal slots vector and resets the hashset to an empty
 * state. Elements are **not** freed; the caller takes ownership of the
 * returned vector and is responsible for iterating the slots and freeing
 * live elements. NULL and tombstone (`(void *)1`) slots must be skipped.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return The slots vector. The caller must call `bf_vector_clean` on it
 *         when done.
 */
struct bf_vector bf_hashset_take(bf_hashset *set);
