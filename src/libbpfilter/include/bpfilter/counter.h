// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include <bpfilter/helper.h>
#include <bpfilter/pack.h>

/**
 * @struct bf_counter
 *
 * Counters assigned to each rule.
 *
 * @var bf_counter::count
 *  Number of events gone through a rule (e.g. packets for packet hooks,
 *  operations for non-packet hooks).
 * @var bf_counter::size
 *  Accumulated size in bytes. Always 0 for non-packet hooks.
 */
struct bf_counter
{
    uint64_t count;
    uint64_t size;
};

#define _free_bf_counter_ __attribute__((__cleanup__(bf_counter_free)))

/**
 * Create a new @ref bf_counter with the given packets and bytes.
 *
 * On success, @p counter is set to the newly allocated @ref bf_counter,
 * owned by the caller.
 *
 * @param counter Output pointer for the new @ref bf_counter. Can't be NULL.
 * @param count Initial event count.
 * @param size  Initial accumulated size.
 * @return 0 on success, negative errno on error.
 */
int bf_counter_new(struct bf_counter **counter, uint64_t count, uint64_t size);

/**
 * @brief Allocate and initialize a new counter from serialized data.
 *
 * @param counter Counter object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*counter` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized counter. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_counter_new_from_pack(struct bf_counter **counter, bf_rpack_node_t node);

/**
 * Free a @ref bf_counter structure.
 *
 * If @p counter is NULL, nothing is done.
 *
 * @param counter Counter to free. Can't be NULL.
 */
void bf_counter_free(struct bf_counter **counter);

/**
 * @brief Serialize a counter.
 *
 * @param counter Counter to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the counter into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
int bf_counter_pack(const struct bf_counter *counter, bf_wpack_t *pack);
