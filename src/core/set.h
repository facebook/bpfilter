// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "core/dump.h"
#include "core/list.h"
#include "core/matcher.h"

/**
 * @file set.h
 *
 * A set represent a set of data of the same type. They allow bpfilter to
 * perform O(1) lookup in large pools of data of the same type.
 *
 * For example, a set would be useful to match a network packet against many
 * different IP addresses. Instead of creating a different rule for each IP
 * address, they could be added into a set and the BPF program would comparing
 * the packet's IP address to the whole set a once.
 *
 * Sets are implemented as BPF hash maps, allowing for O(1) lookup for a given
 * key.
 */

struct bf_marsh;

#define _free_bf_set_ __attribute__((__cleanup__(bf_set_free)))

/// Maximum number of components (matchers) allowed in a set key/element.
#define BF_SET_MAX_N_COMPS 8

/**
 * @brief Set object, used to group data of the same type to speed up filtering.
 *
 * Sets are composed of two key elements:
 * - Key: defines how the data in the set is structure, using `bf_matcher_type`
 *   values.
 * - Elements: values stored in the set, to compare values from the packet
 *   against.
 */
struct bf_set
{
    /** Key of the set. Can't contain more than `BF_SET_MAX_N_COMPS` types. */
    enum bf_matcher_type key[BF_SET_MAX_N_COMPS];

    /** Number of components (types) present in the key. */
    size_t n_comps;

    /** Elements of the set. */
    bf_list elems;

    /** Size of a single element. All elements have the same size, it's derived
     * from the key. */
    size_t elem_size;

    /** If a set key has a single component which filters on a network address,
     * use a LPM trie structure instead of the standard hash map. */
    bool use_trie;
};

/**
 * @brief Allocate and initialise a new set.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param key Key of the set, as an array of `bf_matcher_type`. Not all the
 *        matcher types can be used as set key components. Can't be NULL.
 * @param n_comps Number of components in `key`.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_new(struct bf_set **set, enum bf_matcher_type *key, size_t n_comps);

/**
 * @brief Allocate and initialise a new set from a raw key and payload values.
 *
 * @param set Set to allocate and initialise. Can't be NULL.
 * @param raw_key Set key, as a string of comma-separated matcher types enclosed
 *        in parentheses. Can't be NULL.
 * @param raw_payload Set payload, to parse according to `raw_key`. Can't be
 *        NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_set_new_from_raw(struct bf_set **set, const char *raw_key,
                        const char *raw_payload);

int bf_set_new_from_marsh(struct bf_set **set, const struct bf_marsh *marsh);
void bf_set_free(struct bf_set **set);
int bf_set_marsh(const struct bf_set *set, struct bf_marsh **marsh);
void bf_set_dump(const struct bf_set *set, prefix_t *prefix);

int bf_set_add_elem(struct bf_set *set, void *elem);
