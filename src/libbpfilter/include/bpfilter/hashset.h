/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/dump.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/vector.h>

/**
 * @file hashset.h
 *
 * Open-addressing hashset with linear probing, backed by @ref bf_vector.
 * Elements are fixed-size blobs compared with @c memcmp. Uses FNV-1a for
 * hashing. Removed elements leave tombstones; no compaction is performed.
 */

struct bf_hashset;

#define _free_bf_hashset_ __attribute__((cleanup(bf_hashset_free)))

/// Maximum number of components (matchers) allowed in a hashset key/element.
#define BF_HASHSET_MAX_N_COMPS 8

/**
 * @struct bf_hashset
 *
 * @var bf_hashset::slots
 *  Backing vector. Each element in the vector is a status byte followed
 *  by @c elem_size bytes of element data.
 * @var bf_hashset::elem_size
 *  Size of a single element in bytes (not including the status byte).
 * @var bf_hashset::len
 *  Number of occupied slots (not counting tombstones).
 * @var bf_hashset::n_used
 *  Number of occupied + tombstone slots (used for load factor).
 * @var bf_hashset::name
 *  Name of the set. If NULL, the set is anonymous.
 * @var bf_hashset::key
 *  Key defining how elements are structured, using @c bf_matcher_type values.
 * @var bf_hashset::n_comps
 *  Number of components (types) present in the key.
 * @var bf_hashset::use_trie
 *  If the key has a single network address component, use LPM trie.
 */
struct bf_hashset
{
    struct bf_vector slots;
    size_t elem_size;
    size_t len;
    size_t n_used;

    const char *name;
    enum bf_matcher_type key[BF_HASHSET_MAX_N_COMPS];
    size_t n_comps;
    bool use_trie;
};

/**
 * @brief Allocate and initialise a new hashset.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param name Name of the set, can be used to identify it. If NULL, the set
 *        is anonymous.
 * @param key Key of the set, as an array of `bf_matcher_type`. Not all the
 *        matcher types can be used as set key components. Can't be NULL.
 * @param n_comps Number of components in `key`.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_new(struct bf_hashset **set, const char *name,
                   enum bf_matcher_type *key, size_t n_comps);

/**
 * @brief Free a hashset.
 *
 * @param set Pointer to the hashset pointer. Must be non-NULL.
 */
void bf_hashset_free(struct bf_hashset **set);

/**
 * @brief Get the number of elements in the hashset.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return Number of elements stored.
 */
size_t bf_hashset_size(const struct bf_hashset *set);

/**
 * @brief Get the current number of slots.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return Current slot count.
 */
size_t bf_hashset_cap(const struct bf_hashset *set);

/**
 * @brief Check if the hashset is empty.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @return True if the hashset has no elements.
 */
bool bf_hashset_is_empty(const struct bf_hashset *set);

const char *bf_hashset_get_name(const struct bf_hashset *set);
size_t bf_hashset_get_n_comps(const struct bf_hashset *set);
enum bf_matcher_type bf_hashset_get_key_comp(const struct bf_hashset *set,
                                             size_t index);

/**
 * @brief Check whether an element exists in the hashset.
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param elem Element to look up. Must be non-NULL.
 * @return True if @p elem is present.
 */
bool bf_hashset_contains(const struct bf_hashset *set, const void *elem);

/**
 * @brief Remove an element from the hashset.
 *
 * The slot is marked as a tombstone; no memory is reclaimed.
 * Removing an element that doesn't exist is a no-op (returns 0).
 *
 * @param set Initialised hashset. Must be non-NULL.
 * @param elem Element to remove. Must be non-NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_remove(struct bf_hashset *set, const void *elem);

/**
 * @brief Add all elements from @p to_add into @p dest, then free @p to_add.
 *
 * Duplicate elements are skipped. Both hashsets must have the same
 * key format. On success, @p *to_add is freed and set to NULL.
 *
 * @param dest Destination hashset. Can't be NULL.
 * @param to_add Source hashset. Can't be NULL. Freed on success.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_add_many(struct bf_hashset *dest, struct bf_hashset **to_add);

/**
 * @brief Remove all elements in @p to_remove from @p dest, then free
 * @p to_remove.
 *
 * Elements in @p to_remove that aren't in @p dest are ignored. Both hashsets
 * must have the same key format. On success, @p *to_remove is freed and
 * set to NULL.
 *
 * @param dest Destination hashset. Can't be NULL.
 * @param to_remove Source hashset. Can't be NULL. Freed on success.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_remove_many(struct bf_hashset *dest,
                           struct bf_hashset **to_remove);

/**
 * @brief Allocate and initialise a new hashset from raw key and payload.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param name Name of the set. If NULL, the set is anonymous.
 * @param raw_key Set key as comma-separated matcher types in parentheses.
 *        Can't be NULL.
 * @param raw_payload Set payload to parse according to @p raw_key. Can't
 *        be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_new_from_raw(struct bf_hashset **set, const char *name,
                            const char *raw_key, const char *raw_payload);

/**
 * @brief Allocate and initialise a new hashset from serialized data.
 *
 * @param set Set to allocate and initialise. Can't be NULL. On failure,
 *        @p *set is unchanged.
 * @param node Node containing the serialized set. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_new_from_pack(struct bf_hashset **set, bf_rpack_node_t node);

/**
 * @brief Serialize a hashset.
 *
 * @param set Set to serialize. Can't be NULL.
 * @param pack @c bf_wpack_t object to serialize into. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_pack(const struct bf_hashset *set, bf_wpack_t *pack);

/**
 * @brief Dump a human-readable representation of the hashset.
 *
 * @param set Hashset to dump. Can't be NULL.
 * @param prefix Dump prefix for indentation. Can't be NULL.
 */
void bf_hashset_dump(const struct bf_hashset *set, prefix_t *prefix);

/**
 * @brief Insert an element into the hashset.
 *
 * If the element already exists, no duplicate is added and 0 is returned.
 * The hashset grows automatically when the load factor is exceeded.
 *
 * @param set Initialised hashset. Can't be NULL.
 * @param elem Pointer to the element to insert. Can't be NULL and must point
 *        to at least @c elem_size bytes.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_add_elem(struct bf_hashset *set, const void *elem);

/**
 * @brief Parse a raw element string and insert it into a hashset.
 *
 * The element is parsed according to @p set->key.
 *
 * @param set Set to insert the element into. Can't be NULL.
 * @param raw_elem Raw element to parse. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_hashset_add_elem_raw(struct bf_hashset *set, const char *raw_elem);

/// Status byte value for an occupied slot in @ref bf_hashset.
#define _BF_HASHSET_SLOT_OCCUPIED 1

/**
 * @brief Iterate over all occupied elements in a hashset.
 *
 * @param set Pointer to the hashset to iterate over. Must be non-NULL.
 * @param elem_var Name of the void* variable to hold each element.
 */
#define bf_hashset_foreach(set, elem_var)                                      \
    for (size_t _bf_hset_idx = 0, _bf_hset_brk = 0;                            \
         _bf_hset_idx < bf_hashset_cap(set) && !_bf_hset_brk; ++_bf_hset_idx)  \
        if (*(uint8_t *)bf_vector_get(&(set)->slots, _bf_hset_idx) !=          \
            _BF_HASHSET_SLOT_OCCUPIED)                                         \
            continue;                                                          \
        else                                                                   \
            for (void *(elem_var) =                                            \
                     (_bf_hset_brk = 1,                                        \
                     (void *)((uint8_t *)bf_vector_get(&(set)->slots,          \
                                                       _bf_hset_idx) +         \
                              sizeof(uint8_t)));                               \
                 _bf_hset_brk; _bf_hset_brk = 0)
