/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file hashset.h
 *
 * Open-addressing hashset with linear probing that preserves insertion order.
 * Backed by an array of `bf_hashset_elem` slots; each slot holds a data
 * pointer plus prev/next pointers that thread a doubly-linked list through
 * the live elements. Iteration via `bf_hashset_foreach` yields elements
 * in insertion order. Uses user-provided callbacks (with an opaque context
 * pointer) for hashing, comparison, and cleanup.
 */

typedef uint64_t (*bf_hashset_ops_hash)(const void *data, void *ctx);
typedef bool (*bf_hashset_ops_equal)(const void *lhs, const void *rhs,
                                     void *ctx);
typedef void (*bf_hashset_ops_free)(void **data, void *ctx);

/**
 * @brief Callbacks for hashset element operations.
 */
typedef struct
{
    /// Hash function for an element. Must be non-NULL.
    bf_hashset_ops_hash hash;
    /// Equality comparison for two elements. Must be non-NULL.
    bf_hashset_ops_equal equal;
    /// Free callback for an element. If NULL, elements won't be freed.
    bf_hashset_ops_free free;
} bf_hashset_ops;

/**
 * @brief Element node stored in a hashset, maintaining an insertion-order
 *        linked list.
 *
 * @warning From the user's perspective, the inside of this structure should
 * not be directly accessed. Directly modifying any of the fields should be
 * considered undefined behavior.
 */
typedef struct bf_hashset_elem
{
    /// User-provided data pointer.
    void *data;
    /// Previous element in insertion order, or NULL if first.
    struct bf_hashset_elem *prev;
    /// Next element in insertion order, or NULL if last.
    struct bf_hashset_elem *next;
} bf_hashset_elem;

/**
 * @brief Open-addressing hashset with linear probing. Preserves insertion
 *        order.
 *
 * @warning From the user's perspective, the inside of this structure should
 * not be directly accessed. Directly modifying any of the fields should be
 * considered undefined behavior.
 */
typedef struct bf_hashset
{
    /// Backing array of slot pointers.
    bf_hashset_elem **slots;
    /// Number of allocated slots.
    size_t cap;
    /// Number of live elements (not counting tombstones).
    size_t len;
    /// Number of occupied + tombstone slots (used for load factor).
    size_t slots_in_use;
    /// Callbacks for hashing, comparing, and freeing elements.
    bf_hashset_ops ops;
    /// Opaque context pointer passed to every callback.
    void *ctx;
    /// First element in insertion order, or NULL if empty.
    bf_hashset_elem *head;
    /// Last element in insertion order, or NULL if empty.
    bf_hashset_elem *tail;
} bf_hashset;

/**
 * @brief Compound literal for stack-initialising an empty hashset.
 *
 * @param ops_ptr Pointer to a `bf_hashset_ops` struct. Must be non-NULL.
 * @param ctx_ptr Opaque context pointer. Can be NULL.
 * @return An initialised, empty `bf_hashset` value.
 */
#define bf_hashset_default(ops_ptr, ctx_ptr)                                   \
    ((bf_hashset) {.ops = *(ops_ptr), .ctx = (ctx_ptr)})

#define _free_bf_hashset_ __attribute__((cleanup(bf_hashset_free)))
#define _clean_bf_hashset_ __attribute__((cleanup(bf_hashset_clean)))

/**
 * @brief Iterate over all elements in a hashset in insertion order.
 *
 * Unsafe to add elements during iteration (can cause rehashing).
 * Safe to `bf_hashset_delete` the current element during iteration.
 *
 * @param set Pointer to the hashset. Must be non-NULL.
 * @param elem_var Name of the `bf_hashset_elem *` variable to hold each
 *                 element. Access the stored data via `elem_var->data`.
 */
#define bf_hashset_foreach(set, elem_var)                                      \
    for (bf_hashset_elem * (elem_var) = (set)->head,                           \
                           *__next = (set)->head ? (set)->head->next : NULL;   \
         (elem_var);                                                           \
         (elem_var) = __next, __next = __next ? __next->next : NULL)

/**
 * @brief Allocate and initialise a new hashset.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param ops Callbacks for hashing, comparing, and freeing elements.
 *            `hash` and `equal` must be non-NULL. Can't be NULL.
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
 * @brief Initialise a hashset in place.
 *
 * @param set Set to initialise. Can't be NULL.
 * @param ops Callbacks for hashing, comparing, and freeing elements.
 *            `hash` and `equal` must be non-NULL. Can't be NULL.
 * @param ctx Opaque context pointer passed to every callback. Can be NULL.
 */
void bf_hashset_init(bf_hashset *set, const bf_hashset_ops *ops, void *ctx);

/**
 * @brief Clean up a hashset, freeing all elements and the backing buffer.
 *
 * After this call the hashset is empty and can be reused. Do not use on
 * a hashset allocated with `bf_hashset_new()`; use `bf_hashset_free()`
 * instead.
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
size_t bf_hashset_size(const bf_hashset *set);

/**
 * @brief Check if the hashset is empty.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return True if the hashset has no elements.
 */
bool bf_hashset_is_empty(const bf_hashset *set);

/**
 * @brief Pre-allocate capacity for at least `count` elements.
 *
 * Ensures the backing array is large enough to hold `count` elements without
 * exceeding the load factor. If the current capacity is already sufficient,
 * this is a no-op. Existing elements are preserved.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param count Expected number of elements.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_reserve(bf_hashset *set, size_t count);

/**
 * @brief Insert an element into the hashset.
 *
 * If the element already exists, no duplicate is added and `-EEXIST` is
 * returned; ownership of `*data` is not transferred in that case.
 * The hashset grows automatically when the load factor is exceeded.
 * On successful insertion, the hashset takes ownership of `*data`,
 * appends it to the end of the iteration order, and sets `*data` to NULL.
 *
 * @param set Initialised hashset. Can't be NULL.
 * @param data Pointer to the data pointer. Must be non-NULL, `*data` must
 *             be non-NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_add(bf_hashset *set, void **data);

/**
 * @brief Check whether an element exists in the hashset.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param data Element to look up. Must be non-NULL.
 * @return True if a matching element is present.
 */
bool bf_hashset_contains(const bf_hashset *set, const void *data);

/**
 * @brief Delete an element from the hashset.
 *
 * The slot is marked as a tombstone and the element is unlinked from the
 * iteration order. The element is freed using the `free` callback if one
 * was provided.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param data Element to delete. Must be non-NULL.
 * @return 0 on success, `-ENOENT` if the element is not found, or a negative
 *         errno value on failure.
 */
int bf_hashset_delete(bf_hashset *set, const void *data);

/**
 * @brief Remove an element from the hashset and return its data to the caller.
 *
 * Looks up the element matching `key`, unlinks it from the iteration order,
 * and marks the slot as a tombstone. Unlike `bf_hashset_delete`, the `free`
 * callback is not invoked and ownership of the stored pointer is transferred
 * to the caller through `*data`.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param key Element to look up. Must be non-NULL.
 * @param data Location to receive the taken data pointer. Must be non-NULL.
 * @return 0 on success, `-ENOENT` if the element is not found, or a negative
 *         errno value on failure.
 */
int bf_hashset_take(bf_hashset *set, const void *key, void **data);
