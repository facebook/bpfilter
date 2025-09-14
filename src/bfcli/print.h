
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include <bpfilter/list.h>
#include <bpfilter/runtime.h>

struct bf_chain;
struct bf_hookopts;

/**
 * Print a single chain.
 *
 * @param chain Chain to print. Can't be NULL.
 * @param hookopts Chain's hook options. If NULL, it is assumed the chain is not
 *        attached to a hook.
 * @param counters List of counters for the chain. This function expects the
 *        first to entries in the list to be the policy and error counters.
 *        Then, every rule should have an entry in the list in the order they
 *        are defined, even if the rule doesn't have counters enabled.
 */
void bfc_chain_dump(struct bf_chain *chain, struct bf_hookopts *hookopts,
                    bf_list *counters);

/**
 * Print ruleset information and counters to the console.
 *
 * @param chains List of chains to print.
 * @param hookopts List of hookoptions to print.
 * @param counters List of counters to print.
 */
int bfc_ruleset_dump(bf_list *chains, bf_list *hookopts, bf_list *counters);

/**
 * @brief Print a logged packet published by a rule.
 *
 * @pre
 * - `log != NULL`
 *
 * @param log Logged data.
 */
void bfc_print_log(const struct bf_log *log);
