/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

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
 * `bf_chain_get()`.
 */

/**
 * Create a new hook options object.
 *
 * `bf_hook_opts_get()` expects pairs of `bf_hook_opt` key and value, with the
 * last variadic argument being `-1`:
 *
 * @code{.c}
 *  bf_hook_opts_get(
 *      BF_HOOK_OPT_IFINDEX, 2,
 *      BF_HOOK_OPT_NAME, "my_bpf_program",
 *      -1
 *  );
 * @endcode
 *
 * @param opt First hook option. This parameter is required as C requires at
 *        least one explicit parameter.
 * @return A `bf_hook_opts` structure filled with the arguments passed to the
 *         function. If an error occurs, an error message is printed and the
 *         `bf_hook_opts` structure is filled with `0`.
 */
struct bf_hook_opts bf_hook_opts_get(enum bf_hook_opt opt, ...);

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
 * See `bf_chain_get()` for details of the arguments.
 *
 * @return 0 on success, or a negative errno value on error.
 */
struct bf_chain *bf_chain_get(enum bf_hook hook, struct bf_hook_opts hook_opts,
                              enum bf_verdict policy, struct bf_set **sets,
                              struct bf_rule **rules);
