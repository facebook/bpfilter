/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netfilter_ipv4/ip_tables.h>

/**
 * @brief Check whether @p hook is enabled in @p ipt_replace structure.
 *
 * @param replace @p ipt_replace structure.
 * @param hook Hook to test.
 * @return 0 if @p hook is not enabled, any value otherwise.
 */
#define ipt_is_hook_enabled(replace, hook)                                     \
    ((replace)->valid_hooks & (1 << (hook)))

/**
 * @brief Get @p ipt_entry's match at @p offset.
 *
 * @param entry @p ipt_entry structure the get the match from. Must
 * 	be non-NULL.
 * @param offset Offset of the match to get.
 *
 * @return Pointer to the match at @p offset in @p ipt_entry.
 */
#define ipt_get_match(entry, offset)                                           \
    ((struct ipt_entry_match *)((void *)(entry) + (offset)))

/**
 * @brief Get @p ipt_entry's target.
 *
 * @param entry @p ipt_entry structure to get the target from.
 * @return Pointer to the target assigned to @p ipt_entry.
 */
#define ipt_get_target(entry)                                                  \
    (struct ipt_entry_target *)((void *)(entry) + (entry)->target_offset)

/**
 * @brief Get first rule for @p hook in @p ipt_replace.
 * @param replace @p ipt_replace structure.
 * @param hook Hook to get the first rule for.
 * @return Pointer to the first rule for @p hook.
 */
#define ipt_get_first_rule(replace, hook)                                      \
    (struct ipt_entry *)((void *)(replace)->entries +                          \
                         (replace)->hook_entry[hook])

/**
 * @brief Get rule following @p ipt_entry.
 *
 * @param entry @p ipt_entry structure.
 * @return Pointer to the next rule.
 */
#define ipt_get_next_rule(entry)                                               \
    (struct ipt_entry *)((void *)(entry) + (entry)->next_offset)

/**
 * @brief Get last rule for @p hook in @p ipt_replace.
 *
 * @param replace @p ipt_replace structure.
 * @param hook Hook to get the last rule for.
 * @return Pointer to the last rule for @p hook.
 */
#define ipt_get_last_rule(replace, hook)                                       \
    (struct ipt_entry *)((void *)(replace)->entries +                          \
                         (replace)->underflow[hook])
