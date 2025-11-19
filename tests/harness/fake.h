/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdio.h>

#include <bpfilter/list.h>

typedef bool (*bft_list_eq_cb)(const void *, const void *);
typedef int (*bft_list_dummy_inserter)(bf_list *, void *);

/**
 * @brief Create a test list with fake data.
 *
 * The list will be filled with `len` elements, each element being a pointer
 * to `size_t` value. The pointed values will be from 0 to `len - 1`.
 *
 * The `free` and `pack` callbacks are populated, so the list can be cleaned
 * up and serialized, list any other list.
 *
 * @param len Number of elements to insert in the list.
 * @param inserter Callback to insert data in the list. `bf_list_add_tail` or
 *        `bf_list_add_head` can be used. Can be NULL if `len` is 0.
 * @return A pointer to a valid list on success, or a NULL pointer on failure.
 */
bf_list *bft_list_dummy(size_t len, bft_list_dummy_inserter inserter);

/**
 * @brief Packing callback for `bft_list_dummy` node's payload.
 *
 * @param data Node's payload to pack.
 * @param pack Packing object.
 * @return 0 on success, or a negative error value on failure.
 */
int bft_list_dummy_pack(const void *data, bf_wpack_t *pack);

/**
 * @brief Comparaison callback for lists filled using `bft_list_dummy`.
 *
 * @param lhs First list's node payload.
 * @param rhs Second list's node payload.
 * @return True if the `lhs` is equal to `rhs`, false otherwise.
 */
bool bft_list_dummy_eq(const void *lhs, const void *rhs);

const void *bft_get_randomly_filled_buffer(size_t len);

struct bf_chain *bft_chain_dummy(bool with_rules);
struct bf_rule *bft_rule_dummy(size_t n_matchers);
struct bf_matcher *bft_matcher_dummy(const void *data, size_t data_len);
struct bf_set *bft_set_dummy(size_t n_elems);
