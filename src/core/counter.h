// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/helper.h"
#include "core/marsh.h"

/**
 * @struct bf_counter
 *
 * Counters assigned to each rule.
 *
 * @var bf_counter::packets
 *  Number of packets gone through a rule.
 * @var bf_counter::bytes
 *  Number of bytes gone through a rule.
 */
struct bf_counter
{
    uint64_t packets;
    uint64_t bytes;
} bf_packed;

#define _cleanup_bf_counter_ __attribute__((__cleanup__(bf_counter_free)))

/**
 * Free a @ref bf_counter structure.
 *
 * If @p counter is NULL, nothing is done.
 *
 * @param counter Counter to free. Can't be NULL.
 */
void bf_counter_free(struct bf_counter **counter);

/**
 * Create a new @ref bf_counter with the given packets and bytes.
 *
 * On success, @p counter is set to the newly allocated @ref bf_counter,
 * owned by the caller.
 *
 * @param counter Output pointer for the new @ref bf_counter. Can't be NULL.
 * @param packets Initial packet count.
 * @param bytes   Initial byte count.
 * @return 0 on success, negative errno on error.
 */
int bf_counter_new(struct bf_counter **counter, uint64_t packets,
                   uint64_t bytes);

/**
 * Marshal a @ref bf_counter into a @ref bf_marsh object.
 *
 * The resulting marsh contains two children: @c packets and @c bytes.
 * On success, @p marsh is set to the new @ref bf_marsh, owned by the caller.
 *
 * @param counter Counter to marshal. Can't be NULL.
 * @param marsh   Output pointer for the @ref bf_marsh. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_counter_marsh(const struct bf_counter *counter, struct bf_marsh **marsh);

/**
 * Create a @ref bf_counter from a @ref bf_marsh.
 *
 * Reads two children (for @c packets and @c bytes). On success, @p counter
 * is set to the new @ref bf_counter, owned by the caller.
 *
 * @param counter Output pointer for the new @ref bf_counter. Can't be NULL.
 * @param marsh   Marsh containing the @c packets and @c bytes. Can't be NULL.
 * @return 0 on success, negative errno on error.
 */
int bf_counter_new_from_marsh(struct bf_counter **counter,
                              const struct bf_marsh *marsh);
