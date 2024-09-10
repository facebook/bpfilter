/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/counter.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/verdict.h"

struct bf_marsh;
struct bf_program;

#define _cleanup_bf_cgen_ __attribute__((cleanup(bf_cgen_free)))

/**
 * @struct bf_cgen
 *
 * Codegen are used to represent filtering rules to be applied for a given
 * front, at a given location in the network stack. It contains a list of
 * programs, which are BPF program aimed to be attached to a given interface.
 * Hence, not all rules have to target all interfaces.
 *
 * @var bf_cgen::hook
 * Hook to attach the programs to.
 * @var bf_cgen::front
 * Source of the filtering rules.
 * @var bf_cgen::rules
 * List of rules defined by the front, to be attached at @p hook.
 * @var bf_cgen::programs
 * List of generated BPF programs for this codegen. One program per interface
 * should be expected, except for the loopback interface.
 */
struct bf_cgen
{
    enum bf_hook hook;
    enum bf_front front;

    /** Codegen policy: verdict to be applied by default by the codegen, unless
     * one of the rules matches the packet. */
    enum bf_verdict policy;

    bf_list rules;
    bf_list programs;
};

/**
 * Allocate and initialise a new codegen.
 *
 * @param cgen Codegen to initialise. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_new(struct bf_cgen **cgen);

/**
 * Free a codegen.
 *
 * If one or more programs are loaded, they won't be unloaded. Use @ref
 * bf_cgen_unload first to ensure programs are unloaded. This behaviour
 * is expected so @ref bf_cgen can be freed without unloading the BPF
 * program, during a daemon restart for example.
 *
 * @param cgen Codegen to free. Can't be NULL.
 */
void bf_cgen_free(struct bf_cgen **cgen);

/**
 * Update the BPF programs for a codegen.
 *
 * @param cgen Codegen to update. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_update(struct bf_cgen *cgen);

/**
 * Create a @ref bf_program for each interface, generate the program, load it,
 * and attach it to the kernel.
 *
 * Simplify @ref bf_program management by providing a single call to add the
 * programs to the systems, starting from a new @ref bf_cgen.
 *
 * @param cgen Codegen to generate the programs for, and load to the system.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_cgen_up(struct bf_cgen *cgen);

/**
 * Unload a codegen's BPF programs.
 *
 * @param cgen Codegen containing the BPF program to unload. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_cgen_unload(struct bf_cgen *cgen);

int bf_cgen_marsh(const struct bf_cgen *cgen, struct bf_marsh **marsh);

int bf_cgen_unmarsh(const struct bf_marsh *marsh, struct bf_cgen **cgen);

void bf_cgen_dump(const struct bf_cgen *cgen, prefix_t *prefix);

/**
 * Get a codegen's BPF program for a given interface.
 *
 * @param cgen Codegen containing the BPF program to get. Can't be NULL.
 * @param ifindex Interface to get the BPF program for.
 * @return BPF program for the given interface, or NULL if not found.
 */
struct bf_program *bf_cgen_get_program(const struct bf_cgen *cgen,
                                       uint32_t ifindex);

/**
 * Get packets and bytes counter at a specific index.
 *
 * Counters are referenced by their index in the counters map. There are 1 more
 * counter in the map than the number of rules. This last counter (the last in
 * the map) is dedicated to the policy.
 *
 * The counter from all the program generated from @p cgen are summarised
 * together.
 *
 * @param cgen Codegen to get the counter for. Can't be NULL.
 * @param counter_idx Index of the counter to get. If @p counter_idx doesn't
 *        correspond to a valid index, -E2BIG is returned.
 * @param counter Counter structure to fill with the counter values. Can't be
 *        NULL.
 * @return 0 on success, or a negative errno  value on failure.
 */
int bf_cgen_get_counter(const struct bf_cgen *cgen, uint32_t counter_idx,
                        struct bf_counter *counter);
