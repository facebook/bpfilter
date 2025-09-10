/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/pack.h"
#include "core/verdict.h"

struct bf_hookopts;
struct bf_matcher;
struct bf_rule;

#define _free_bf_chain_ __attribute__((cleanup(bf_chain_free)))

/**
 * @brief Features used by the rules defined in the chain.
 *
 * Some features used by the rules have an impact at the chain or program level,
 * these flags are used to define which feature is used at the chain level,  and
 * generate the bytecode accordingly.
 *
 * For example, a pointer to the log ring buffer is store in the program's
 * runtime context. This pointer should not be populated if no rule is has a
 * 'log' instruction.
 *
 * Grouping the list of required features at the chain level prevents us from
 * parsing all the rules and matchers everytime the feature would affect the
 * bytecode.
 */
enum bf_chain_flags
{
    /** A rule will log data to the ring buffer. */
    BF_CHAIN_LOG,

    /** A rule will filter on IPv6 nexthdr field. */
    BF_CHAIN_STORE_NEXTHDR,

    _BF_CHAIN_FLAGS_MAX,
};

struct bf_chain
{
    const char *name;
    uint8_t flags;
    enum bf_hook hook;
    enum bf_verdict policy;
    bf_list sets;
    bf_list rules;
};

/**
 * Allocate and initialize a `bf_chain` object.
 *
 * The content of `sets` and `rules` is stolen by the constructor if the
 * function succeeds, in which case the source lists are empty and the chain
 * is responsible for the data. Otherwise, both list are unchanged.
 *
 * @param chain `bf_chain` object to allocate and initialize. On failure,
 *        this parameter is unchanged. Can't be NULL.
 * @param name Name of the chain. Can't be NULL.
 * @param hook Expected hook to attach the chain to.
 * @param policy Default action of the chain if no rule matched.
 * @param sets List of sets used by `rules`.
 * @param rules List of rules.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules);

/**
 * @brief Allocate and initialize a new chain from serialized data.
 *
 * @param chain Chain object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*chain` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_new_from_pack(struct bf_chain **chain, bf_rpack_node_t node);

/**
 * Deallocate a `bf_chain` object.
 *
 * @param chain `bf_chain` object to cleanup and deallocate. If `*chain`
 *        is NULL, this function has no effect. Can't be NULL.
 */
void bf_chain_free(struct bf_chain **chain);

/**
 * @brief Serialize a chain.
 *
 * @param chain Chain to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the chain into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_chain_pack(const struct bf_chain *chain, bf_wpack_t *pack);

/**
 * Dump the content of a `bf_chain` object.
 *
 * @param chain `bf_chain` object to print. Can't be NULL.
 * @param prefix Prefix to use for the dump. Can't be NULL.
 */
void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix);

/**
 * Insert a rule into the chain.
 *
 * The chain will own the rule and is responsible for freeing it. The rule's
 * index will automatically be updated.
 *
 * @param chain Chain to insert the rule into. Can't be NULL.
 * @param rule Rule to insert into the chain. Can't be NULL.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule);

/**
 * @brief Get the set used by a matcher.
 *
 * @param chain Chain to get the set from. Can't be NULL.
 * @param matcher Matching filtering on a set. Can't be NULL.
 * @return The set `matcher` filters on, or NULL if the set can't be found or
 *         if `matcher->type` is not `BF_MATCHER_SET`.
 */
struct bf_set *bf_chain_get_set_for_matcher(const struct bf_chain *chain,
                                            const struct bf_matcher *matcher);
