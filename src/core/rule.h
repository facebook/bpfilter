/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/dump.h"
#include "core/list.h"
#include "core/matcher.h"
#include "core/runtime.h"
#include "core/verdict.h"

struct bf_marsh;

/**
 * @brief Return the string representation of a `bf_pkthdr` enumeration value.
 * *
 * @param hdr `bf_pkthdr` enumeration value.
 * @return A pointer to the C-string representation of `hdr`.
 */
const char *bf_pkthdr_to_str(enum bf_pkthdr hdr);

/**
 * @brief Return the `bf_pkthdr` enumeration value corresponding to a string.
 *
 * @pre
 * - `str` is a non-NULL pointer to a C-string.
 * - `hdr != NULL`
 * @post
 * - On failure, `hdr` is unchanged.
 *
 * @param str String to get the corresponding `bf_pkthdr` enumeration value for.
 * @param hdr On success, contains the `bf_pkthdr` enumeration value
 *        corresponding to `str`.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_pkthdr_from_str(const char *str, enum bf_pkthdr *hdr);

#define _free_bf_rule_ __attribute__((__cleanup__(bf_rule_free)))

/**
 * Convenience macro to initialize a list of @ref bf_rule .
 *
 * @return An initialized @ref bf_list that can contain @ref bf_rule objects.
 */
#define bf_rule_list()                                                         \
    ((bf_list) {.ops = {.free = (bf_list_ops_free)bf_rule_free,                \
                        .marsh = (bf_list_ops_marsh)bf_rule_marsh}})

/**
 * @struct bf_rule
 *
 * Represents a rule to match against packets.
 *
 * @var bf_rule::index
 *  Rule's index. Identifies the rule's within other rules from the same front.
 */
struct bf_rule
{
    uint32_t index;
    bf_list matchers;
    uint8_t log;
    bool counters;
    enum bf_verdict verdict;
};

static_assert(
    _BF_PKTHDR_MAX < 8,
    "bf_pkthdr has more than 8 values, it won't fit in bf_rule.log's 8 bits");

/**
 * Allocated and initialise a new rule.
 *
 * On failure, @p rule is left unchanged.
 *
 * @param rule On success, points to the allocated rule. Must be non NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_rule_new(struct bf_rule **rule);

/**
 * Free a rule.
 *
 * Free @p rule and set it to NULL. If @p rule is NULL, nothing is done.
 *
 * @param rule Rule to free. Must be non-NULL.
 */
void bf_rule_free(struct bf_rule **rule);

/**
 * Marsh a rule.
 *
 * @param rule Rule to marsh. Can't be NULL.
 * @param marsh Output marshalled rule. Allocated by the function, owned by
 *        the caller once the function returns. Can't be NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_rule_marsh(const struct bf_rule *rule, struct bf_marsh **marsh);

/**
 * Unmarsh a rule.
 *
 * @param marsh Marshalled rule. Must be non NULL.
 * @param rule Unmarshalled rule. Allocated by the function, owned by the caller
 *        on success.
 * @return 0 on success, negative errno value on error.
 */
int bf_rule_unmarsh(const struct bf_marsh *marsh, struct bf_rule **rule);

/**
 * Dump a rule.
 *
 * @param rule Rule to dump. Must not be NULL.
 * @param prefix Prefix for each printed line.
 */
void bf_rule_dump(const struct bf_rule *rule, prefix_t *prefix);

/**
 * Create a new matcher and add it to the rule.
 *
 * @param rule Rule to add the matcher to. Can't be NULL.
 * @param type Matcher type.
 * @param op Comparison operator.
 * @param payload Payload of the matcher, its content and size depends on @p
 *        type . Can be NULL but only if @p payload_len is 0, in which case
 *        there is no payload.
 * @param payload_len Length of the payload.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_rule_add_matcher(struct bf_rule *rule, enum bf_matcher_type type,
                        enum bf_matcher_op op, const void *payload,
                        size_t payload_len);
