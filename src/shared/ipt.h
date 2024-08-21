/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/netfilter/x_tables.h>

/**
 * @brief Get size of an ipt_replace structure.
 *
 * @param ipt_replace_ptr Pointer to a valid ipt_replace structure.
 * @return Size of the structure, including variable length entries field.
 */
#define bf_ipt_replace_size(ipt_replace_ptr)                                   \
    (sizeof(struct ipt_replace) + (ipt_replace_ptr)->size)

/**
 * @brief Get size of an xt_counters_info structure.
 *
 * @param xt_counters_info_ptr Pointer to a valid xt_counters_info structure.
 * @return Size of the structure, including variable length counters field.
 */
#define bf_xt_counters_info_size(xt_counters_info_ptr)                         \
    (sizeof(struct xt_counters_info) +                                         \
     (xt_counters_info_ptr)->num_counters * sizeof(struct xt_counters))

/**
 * @brief Get size of an ipt_get_entries structure.
 *
 * @param ipt_get_entries_ptr Pointer to a valid ipt_get_entries structure.
 * @return Size of the structure, including variable length entries field.
 */
#define bf_ipt_get_entries_size(ipt_get_entries_ptr)                           \
    (sizeof(struct ipt_get_entries) + (ipt_get_entries_ptr)->size)

/**
 * @brief Get rule from an ipt_entry structure at a given offset.
 *
 * @param ipt_entry_ptr Pointer to a valid ipt_entry structure.
 * @param offset Offset of the rule to get. Must be a valid offset.
 * @return Pointer to the rule at @p offset.
 */
#define bf_ipt_entries_get_rule(ipt_entry_ptr, offset)                         \
    ((struct ipt_entry *)((void *)(ipt_entry_ptr)->entrytable + (offset)))
