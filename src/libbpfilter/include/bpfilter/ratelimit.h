// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include <bpfilter/pack.h>

/**
 * @struct bf_ratelimit
 *
 * Rate limit assigned to each rule
 *
 * @var bf_ratelimit::limit
 *  Number of times the rule can be matched before starting to drop packets.
 */
struct bf_ratelimit
{
    uint64_t limit;
};

#define _free_bf_ratelimit_ __attribute__((__cleanup__(bf_ratelimit_free)))

/**
 * Create a new @ref bf_ratelimit with the given limit.
 *
 * On success, @p ratelimit is set to the newly allocated @ref bf_ratelimit,
 * owned by the caller.
 *
 * @param ratelimit Output pointer for the new @ref bf_ratelimit. Can't be NULL.
 * @param limit Number of matches allowed.
 * @return 0 on success, negative errno on error.
 */
int bf_ratelimit_new(struct bf_ratelimit **ratelimit, int64_t limit);

/**
 * @brief Allocate and initialize a new ratelimit from serialized data.
 *
 * @param ratelimit Rate limit object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*ratelimit` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized ratelimit. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ratelimit_new_from_pack(struct bf_ratelimit **ratelimit,
                               bf_rpack_node_t node);

/**
 * Free a @ref bf_ratelimit structure.
 *
 * If @p ratelimit is NULL, nothing is done.
 *
 * @param ratelimit Rate limit to free. Can't be NULL.
 */
void bf_ratelimit_free(struct bf_ratelimit **ratelimit);

/**
 * @brief Serialize a ratelimit.
 *
 * @param ratelimit Rate limit to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the ratelimit into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_ratelimit_pack(const struct bf_ratelimit *ratelimit, bf_wpack_t *pack);
