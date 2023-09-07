/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdint.h>

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "shared/front.h"

struct bf_marsh;

#define _cleanup_bf_codegen_ __attribute__((cleanup(bf_codegen_free)))

/**
 * @struct bf_codegen
 *
 * Codegen are used to represent filtering rules to be applied for a given
 * front, at a given location in the network stack. It contains a list of
 * programs, which are BPF program aimed to be attached to a given interface.
 * Hence, not all rules have to target all interfaces.
 *
 * @var bf_codegen::hook
 * Hook to attach the programs to.
 * @var bf_codegen::front
 * Source of the filtering rules.
 * @var bf_codegen::rules
 * List of rules defined by the front, to be attached at @p hook.
 * @var bf_codegen::programs
 * List of generated BPF programs for this codegen. One program per interface
 * should be expected, except for the loopback interface.
 */
struct bf_codegen
{
    enum bf_hook hook;
    enum bf_front front;

    bf_list rules;
    bf_list programs;
};

/**
 * @brief Allocate and initialise a new codegen.
 *
 * @param codegen Codegen to initialise. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_codegen_new(struct bf_codegen **codegen);

/**
 * @brief Free a codegen.
 *
 * If one or more programs are loaded, they won't be unloaded. Use @ref
 * bf_codegen_unload first to ensure programs are unloaded. This behaviour
 * is expected so @ref bf_codegen can be freed without unloading the BPF
 * program, during a daemon restart for example.
 *
 * @param codegen Codegen to free. Can't be NULL.
 */
void bf_codegen_free(struct bf_codegen **codegen);

/**
 * @brief Generate BPF programs for a codegen.
 *
 * @param codegen Codegen to generate BPF programs for. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_codegen_generate(struct bf_codegen *codegen);

/**
 * @brief Load the BPF program stored in a codegen.
 *
 * Each program within the codegen will be loaded and attached to its interface.
 *
 * @param codegen Codegen containing the BPF program to load. Can't be NULL.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_codegen_load(struct bf_codegen *codegen);

/**
 * @brief Unload a codegen's BPF programs.
 *
 * @param codegen Codegen containing the BPF program to unload. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_codegen_unload(struct bf_codegen *codegen);

int bf_codegen_marsh(const struct bf_codegen *codegen, struct bf_marsh **marsh);

int bf_codegen_unmarsh(const struct bf_marsh *marsh,
                       struct bf_codegen **codegen);

void bf_codegen_dump(const struct bf_codegen *codegen, prefix_t *prefix);

/**
 * @brief Get a codegen's BPF program for a given interface.
 *
 * @param codegen Codegen containing the BPF program to get. Can't be NULL.
 * @param ifindex Interface to get the BPF program for.
 * @return BPF program for the given interface, or NULL if not found.
 */
struct bf_program *bf_codegen_get_program(const struct bf_codegen *codegen,
                                          uint32_t ifindex);
