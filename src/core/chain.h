/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/verdict.h"

struct bf_hookopts;
struct bf_marsh;
struct bf_rule;

#define _free_bf_chain_ __attribute__((cleanup(bf_chain_free)))

struct bf_chain
{
    const char *name;
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
 * Allocate and initialize a new `bf_chain` object from serialized data.
 *
 * @param chain `bf_chain` object to allocate and initialize from `marsh`.
 *        On failure, this parameter is unchanged. Can't be NULL.
 * @param marsh Serialized data to read a `bf_chain` from. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_new_from_marsh(struct bf_chain **chain,
                            const struct bf_marsh *marsh);

/**
 * Deallocate a `bf_chain` object.
 *
 * @param chain `bf_chain` object to cleanup and deallocate. If `*chain`
 *        is NULL, this function has no effect. Can't be NULL.
 */
void bf_chain_free(struct bf_chain **chain);

/**
 * Serialize a `bf_chain` object.
 *
 * @param chain `bf_chain` object to serialize. Can't be NULL.
 * @param marsh On success, represents the serialized `bf_chain` object. On
 *        failure, this parameter is unchanged. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_chain_marsh(const struct bf_chain *chain, struct bf_marsh **marsh);

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
