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
 * Open-addressing hashset with linear probing, backed by a `void**` array.
 * Each slot is a `void*` pointer. `NULL` means empty, sentinel value 1
 * means tombstone, anything else is a live element. Uses user-provided
 * callbacks (with an opaque context pointer) for hashing, comparison, and
 * cleanup.
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
 * @brief Open-addressing hashset with linear probing.
 */
typedef struct bf_hashset
{
    /// Backing array of `void*` pointers.
    void **slots;
    /// Number of allocated slots.
    size_t cap;
    /// Number of occupied slots (not counting tombstones).
    size_t len;
    /// Number of occupied + tombstone slots (used for load factor).
    size_t slots_in_use;
    /// Callbacks for hashing, comparing, and freeing elements.
    bf_hashset_ops ops;
    /// Opaque context pointer passed to every callback.
    void *ctx;
} bf_hashset;

#define bf_hashset_default(ops_ptr, ctx_ptr)                                   \
    ((bf_hashset) {.ops = *(ops_ptr), .ctx = (ctx_ptr)})

#define _free_bf_hashset_ __attribute__((cleanup(bf_hashset_free)))
#define _clean_bf_hashset_ __attribute__((cleanup(bf_hashset_clean)))

/**
 * @brief Check whether a slot holds the tombstone sentinel.
 *
 * @param slot Slot value to test.
 * @return True if `slot` is the tombstone marker.
 */
bool bf_hashset_slot_is_tombstone(const void *slot);

/**
 * @brief Iterate over all occupied elements in a hashset.
 *
 * Do not add or remove elements during iteration.
 *
 * @param set Pointer to the hashset. Must be non-NULL.
 * @param elem_var Name of the `void *` variable to hold each element.
 */
#define bf_hashset_foreach(set, elem_var)                                      \
    for (size_t _bf_hset_i = 0, _bf_hset_brk = 0;                              \
         !_bf_hset_brk && _bf_hset_i < (set)->cap; ++_bf_hset_i)               \
        if (!(set)->slots[_bf_hset_i] ||                                       \
            bf_hashset_slot_is_tombstone((set)->slots[_bf_hset_i]))            \
            continue;                                                          \
        else                                                                   \
            for (void *(elem_var) =                                            \
                     (_bf_hset_brk = 1, (set)->slots[_bf_hset_i]);             \
                 _bf_hset_brk; _bf_hset_brk = 0)

/**
 * @brief Allocate and initialise a new hashset.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param ops Callbacks for hashing, comparing, and freeing elements.
 *        `hash` and `equal` must be non-NULL. Can't be NULL.
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
 *        `hash` and `equal` must be non-NULL. Can't be NULL.
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
size_t bf_hashset_size(const bf_hashset *set);

/**
 * @brief Get the current number of slots.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return Current slot count.
 */
size_t bf_hashset_cap(const bf_hashset *set);

/**
 * @brief Check if the hashset is empty.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return True if the hashset has no elements.
 */
bool bf_hashset_is_empty(const bf_hashset *set);

/**
 * @brief Insert an element into the hashset.
 *
 * If the element already exists, no duplicate is added and `-EEXIST` is
 * returned; ownership of `data` is not transferred in that case.
 * The hashset grows automatically when the load factor is exceeded.
 * On successful insertion, the hashset takes ownership of `data`.
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
 * @brief Remove an element from the hashset.
 *
 * The slot is marked as a tombstone. The element is freed using the
 * `free` callback if one was provided. Removing an element that doesn't
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
 * Returns the internal slots array and resets the hashset to an empty
 * state. Elements are not freed; the caller takes ownership of the
 * returned array and is responsible for iterating the slots and freeing
 * live elements. `NULL` and tombstone slots (see
 * `bf_hashset_slot_is_tombstone`) must be skipped.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param n_slots If non-NULL, receives the number of slots in the
 *        returned array.
 * @return The slots array, or NULL if the hashset was empty. The caller
 *         must call `free()` on it when done.
 */
void **bf_hashset_take(bf_hashset *set, size_t *n_slots);
