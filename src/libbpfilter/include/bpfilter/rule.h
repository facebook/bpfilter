/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/dump.h>
#include <bpfilter/list.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/runtime.h>
#include <bpfilter/verdict.h>

/**
 * @brief Return the string representation of a `bf_pkthdr` enumeration value.
 *
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
 * @brief Allocate and initialize a new rule from serialized data.
 *
 * @param rule Rule object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*rule` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized rule. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_rule_new_from_pack(struct bf_rule **rule, bf_rpack_node_t node);

/**
 * Free a rule.
 *
 * Free @p rule and set it to NULL. If @p rule is NULL, nothing is done.
 *
 * @param rule Rule to free. Must be non-NULL.
 */
void bf_rule_free(struct bf_rule **rule);

/**
 * @brief Serialize a rule.
 *
 * @param rule Rule to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the matcher rule. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_rule_pack(const struct bf_rule *rule, bf_wpack_t *pack);

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
