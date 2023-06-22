/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/dump.h"
#include "core/list.h"

struct bf_marsh;

#define _cleanup_bf_rule_ __attribute__((__cleanup__(bf_rule_free)))

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
    uint32_t ifindex;
    uint8_t invflags;
    uint32_t src;
    uint32_t dst;
    uint32_t src_mask;
    uint32_t dst_mask;
    uint16_t protocol;
    bf_list matches;
    struct bf_target *target;
};

/**
 * @brief Allocated and initialise a new rule.
 *
 * On failure, @p rule is left unchanged.
 *
 * @param rule On success, points to the allocated rule. Must be non NULL.
 * @return 0 on success, or negative errno value on error.
 */
int bf_rule_new(struct bf_rule **rule);

/**
 * @brief Free a rule.
 *
 * Free @p rule and set it to NULL. If @p rule is NULL, nothing is done.
 *
 * @param rule Rule to free. Must be non-NULL.
 */
void bf_rule_free(struct bf_rule **rule);

/**
 * @brief Marsh a rule.
 *
 * @param rule Rule to marsh. Can't be NULL.
 * @param marsh Output marshalled rule. Allocated by the function, owned by
 *  the caller once the function returns. Can't be NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_rule_marsh(const struct bf_rule *rule, struct bf_marsh **marsh);

/**
 * @brief Unmarsh a rule.
 *
 * @param marsh Marshalled rule. Must be non NULL.
 * @param rule Unmarshalled rule. Allocated by the function, owned by the caller
 *  on success.
 * @return 0 on success, negative errno value on error.
 */
int bf_rule_unmarsh(const struct bf_marsh *marsh, struct bf_rule **rule);

/**
 * @brief Dump a rule.
 *
 * @param rule Rule to dump. Must not be NULL.
 * @param prefix Prefix for each printed line.
 */
void bf_rule_dump(const struct bf_rule *rule, prefix_t *prefix);
