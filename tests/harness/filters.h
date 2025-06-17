/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "core/chain.h"
#include "core/hook.h"
#include "core/matcher.h"
#include "core/rule.h"
#include "core/set.h"
#include "core/verdict.h"

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
        bf_rule_get(true, BF_VERDICT_ACCEPT, bft_fake_matchers),               \
        bf_rule_get(false, BF_VERDICT_ACCEPT, bft_fake_matchers),              \
        bf_rule_get(true, BF_VERDICT_DROP, bft_fake_matchers),                 \
        bf_rule_get(false, BF_VERDICT_DROP, bft_fake_matchers),                \
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
 * Create a new set.
 *
 * @code {.c}
 *  bft_set_get(
 *      BF_SET_IP4,
 *      (struct my_custom_struct []) {
 *          { 0x01, 0x02, 0x03, 0x04 },
 *      },
 *      1
 *  );
 * @endcode
 *
 * The caller owns the set and is responsible for freeing it.
 *
 * @param type Set type. Defines the key size.
 * @param data Array of elements to fill the set with. The elements are
 *        expected to a size defined by their @p type .
 * @param n_elems Number of elements in @p data .
 * @return A valid @ref bf_set on success, or NULL on failure.
 */
struct bf_set *bft_set_get(enum bf_set_type type, void *data, size_t n_elems);

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
struct bf_rule *bf_rule_get(bool counters, enum bf_verdict verdict,
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
