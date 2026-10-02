/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/core/list.h>

/**
 * @file set_group.h
 *
 * A chain's sets are stored in BPF maps. To limit the number of maps, sets
 * are partitioned into groups, and each group is backed by a single BPF map.
 *
 * Hash-keyed sets sharing a key format are placed in the same group.
 * LPM trie sets are never grouped together: each one sits in a group of its
 * own, as an LPM trie lookup always returns the longest-prefix match, which
 * would hide the other sets' bits when prefixes overlap.
 *
 * A group's map value is a bitmask: bit `i % CHAR_BIT` of byte `i / CHAR_BIT`
 * is set if the `i`-th set of the group contains the key. A set's position in
 * its group is its bit index.
 *
 * Groups only depend on the chain: building them from the same chain always
 * leads to the same groups, in the same order.
 */

struct bf_chain;
struct bf_set;

struct bf_set_group
{
    /** Sets backed by the group's map, in the chain's order. For hash-keyed
     * groups, all sets share the same key format; LPM trie groups always hold
     * a single set. Non-owning pointers into the chain's `bf_set` list. Never
     * empty. */
    bf_list sets;
};

/**
 * @brief Partition a chain's sets into groups.
 *
 * @param groups List to store the `bf_set_group` objects into, in the order
 *        their maps should be created. Doesn't need to be initialized. On
 *        success, it is overwritten by an initialized list, which frees the
 *        groups when cleaned: it must not contain groups already, as they
 *        wouldn't be freed. On failure, it is left unchanged. The groups point
 *        to the chain's sets: `chain` must outlive them. Can't be NULL.
 * @param chain Chain to group the sets of. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_set_group_build(bf_list *groups, const struct bf_chain *chain);

/**
 * @brief Find the group containing a set.
 *
 * @param groups List of `bf_set_group` built by `bf_set_group_build()`. Can't
 *        be NULL.
 * @param set Set to find. If NULL, no group is found.
 * @param group_idx If not NULL, set to the index of the group in `groups`.
 *        Unchanged if `set` is not part of any group.
 * @param bit_idx If not NULL, set to the bit index of `set` within the group.
 *        Unchanged if `set` is not part of any group.
 * @return The group containing `set`, or NULL if `set` is not part of any
 *         group (for example, because it is empty).
 */
const struct bf_set_group *bf_set_group_find(const bf_list *groups,
                                             const struct bf_set *set,
                                             size_t *group_idx,
                                             size_t *bit_idx);

/**
 * @brief Get the size of a group's map value.
 *
 * @param group Set group. Can't be NULL.
 * @return Size of the value, in bytes: one bit per set of the group.
 */
size_t bf_set_group_value_size(const struct bf_set_group *group);

/**
 * @brief Compute the value of an element in a group's map.
 *
 * @param group Set group. Can't be NULL.
 * @param elem Element to compute the value of. Can't be NULL.
 * @param value Buffer to write the value to, of at least
 *        `bf_set_group_value_size(group)` bytes. Can't be NULL.
 * @return True if at least one set of the group contains `elem`, false
 *         otherwise.
 */
bool bf_set_group_elem_value(const struct bf_set_group *group, const void *elem,
                             uint8_t *value);
