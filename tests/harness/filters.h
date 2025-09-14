/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bpfilter/chain.h"
#include "bpfilter/hook.h"
#include "bpfilter/matcher.h"
#include "bpfilter/rule.h"
#include "bpfilter/set.h"
#include "bpfilter/verdict.h"

/**
 * @file filters.h
 *
 * Convenience functions to easily create matchers, rules, and chains in order
 * to test `bpfilter`. Those functions are wrapper around the actual API (i.e.
 * `bf_matcher_new()`, `bf_rule_new()`, `bf_chain_new()`) which cut corners when
 * it comes to error handling (e.g. you can't retrieve the actual error code).
 *
 * Some wrappers expect `NULL`-terminated array of pointers, they will take
 * ownership of the pointers and free them if an error occurs during the object
 * creation. Valid pointers in the array located after a `NULL` entry won't be
 * processed nor freed, and `asan` will raise an error. See `bf_rule_get()` and
 * `bf_test_chain_get()`.
 */

#define BF_E2E_NAME "bf_e2e"

// clang-format off
#define bft_fake_matchers                                                      \
    (struct bf_matcher *[])                                                    \
    {                                                                          \
        bf_matcher_get(                                                        \
            BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,                               \
            (uint8_t[]) {0x7d, 0x02, 0x0a, 0x0b, 0xff, 0xff, 0x00, 0x00},      \
            8                                                                  \
        ),                                                                     \
        bf_matcher_get(                                                        \
            BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,                               \
            (uint8_t[]) {0x7e, 0x02, 0x0a, 0x0b, 0xff, 0xff, 0x00, 0x00},      \
            8                                                                  \
        ),                                                                     \
        bf_matcher_get(                                                        \
            BF_MATCHER_IP4_DADDR, BF_MATCHER_EQ,                               \
            (uint8_t[]) {0x7f, 0x02, 0x0a, 0x0b, 0xff, 0xff, 0x00, 0x00},      \
            8                                                                  \
        ),                                                                     \
        NULL,                                                                  \
    }

#define bft_fake_rules                                                         \
    (struct bf_rule *[])                                                       \
    {                                                                          \
        bf_rule_get(0, true, BF_VERDICT_ACCEPT, bft_fake_matchers),            \
        bf_rule_get(0, false, BF_VERDICT_ACCEPT, bft_fake_matchers),           \
        bf_rule_get(0, true, BF_VERDICT_DROP, bft_fake_matchers),              \
        bf_rule_get(0, false, BF_VERDICT_DROP, bft_fake_matchers),             \
        NULL,                                                                  \
    }
// clang-format on

/**
 * Create a new hook options object.
 *
 * `bft_hookopts_get()` expects pairs of `bf_hookopts_type` key and value, with the
 * last variadic argument being `NULL`:
 *
 * @code{.c}
 *  bft_hookopts_get(
 *      "ifindex=2",
 *      "cgpath=/sys/fs/cgroup/user.slice",
 *      NULL
 *  );
 * @endcode
 *
 * @param raw_opt First option to parse, formatted as `$KEY=$VALUE`.
 * @return A `bf_hook_opts` structure filled with the arguments passed to the
 *         function. If an error occurs, an error message is printed and the
 *         `bf_hook_opts` structure is filled with `0`.
 */
struct bf_hookopts *bft_hookopts_get(const char *raw_opt, ...);

/**
 * @brief Create a new test set.
 *
 * @code {.c}
 *  bft_set_get(
 *      (enum bf_matcher_type []){{ BF_MATCHER_IP4_PROTO }}, 1
 *      (uint8_t[]) { IPPROTO_TCP, IPPROTO_UDP, }, 2
 *  );
 * @endcode
 *
 * The caller owns the set and is responsible for freeing it.
 *
 * @param key Array of `bf_matcher_type` defining the key format.
 * @param n_comps Number of matcher types in the key.
 * @param data Array of elements to fill the set with.
 * @param n_elems Number of elements in @p data .
 * @return A valid @ref bf_set on success, or NULL on failure.
 */
struct bf_set *bft_set_get(enum bf_matcher_type *key, size_t n_comps,
                           void *data, size_t n_elems);

/**
 * Create a new matcher.
 *
 * See `bf_matcher_new()` for details of the arguments.
 *
 * @return 0 on success, or a negative errno value on error.
 */
struct bf_matcher *bf_matcher_get(enum bf_matcher_type type,
                                  enum bf_matcher_op op, const void *payload,
                                  size_t payload_len);

/**
 * Create a new rule.
 *
 * See `bf_rule_new()` for details of the arguments.
 *
 * @return 0 on success, or a negative errno value on error.
 */
struct bf_rule *bf_rule_get(uint8_t log, bool counters, enum bf_verdict verdict,
                            struct bf_matcher **matchers);

/**
 * Create a new chain.
 *
 * See `bf_chain_new()` for details of the arguments. The hook options are
 * automatically set to test-friendly values:
 * - `attach`: false
 * - `cgroup`: `<no_cgroup>`
 * - `ifindex`: 1
 * - `name`: `bf_e2e_xxxxxx` with `xxxxxx` replaced with 6 random chars.
 *
 * @return A valid chain pointer on success, or `NULL` on failure.
 */
struct bf_chain *bf_test_chain_get(enum bf_hook hook, enum bf_verdict policy,
                                   struct bf_set **sets,
                                   struct bf_rule **rules);

struct bft_list_dummy_data
{
    size_t id;
    size_t len;
    uint8_t padding[];
};

typedef bool (*bft_list_eq_cb)(const void *lhs, const void *rhs);

int bft_list_dummy_data_new_from_pack(struct bft_list_dummy_data **data,
                                      bf_rpack_node_t node);
int bft_list_dummy_data_pack(struct bft_list_dummy_data *data,
                             bf_wpack_t *pack);
bool bft_list_dummy_data_compare(const struct bft_list_dummy_data *lhs,
                                 const struct bft_list_dummy_data *rhs);
bf_list *bft_list_get(size_t n_elems, size_t elem_size);
bool bft_list_eq(const bf_list *lhs, const bf_list *rhs, bft_list_eq_cb cb);
