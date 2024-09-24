/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stdint.h>

#include "core/dump.h"
#include "core/flavor.h"
#include "core/list.h"

/**
 * @file hook.h
 *
 * bpfilter's BPF programs are attached to hooks in the kernel. This file
 * contains the definitions for the hooks we support.
 */

enum bf_hook
{
    BF_HOOK_XDP,
    BF_HOOK_TC_INGRESS,
    BF_HOOK_NF_PRE_ROUTING,
    BF_HOOK_NF_LOCAL_IN,
    BF_HOOK_NF_FORWARD,
    BF_HOOK_NF_LOCAL_OUT,
    BF_HOOK_NF_POST_ROUTING,
    BF_HOOK_TC_EGRESS,
    _BF_HOOK_MAX,
};

enum bf_hook_opt
{
    BF_HOOK_OPT_IFINDEX,
    _BF_HOOK_OPT_MAX,
};

struct bf_hook_opts
{
    uint32_t used_opts;

    // Options
    uint32_t ifindex;
};

/**
 * Convert a bpfilter hook to a string.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return String representation of the hook.
 */
const char *bf_hook_to_str(enum bf_hook hook);

/**
 * Convert a string to the corresponding hook.
 *
 * @param str String containing the name of a hook.
 * @param hook Hook value, if the parsing succeeds.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_hook_from_str(const char *str, enum bf_hook *hook);

/**
 * Convert a bpfilter hook to a BPF program type.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The BPF program type corresponding to @p hook.
 */
unsigned int bf_hook_to_bpf_prog_type(enum bf_hook hook);

/**
 * Get the expected flavor for a given hook.
 *
 * @param hook BPF hook. Must be valid.
 * @return bpfilter flavor corresponding to @p hook.
 */
enum bf_flavor bf_hook_to_flavor(enum bf_hook hook);

/**
 * Convert a bpfilter hook to a BPF attach type.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The BPF attach type corresponding to @p hook.
 */
enum bpf_attach_type bf_hook_to_attach_type(enum bf_hook hook);

/**
 * Initializes a hook options structure.
 *
 * @param opts Hook options structure to initialize. Can't be NULL.
 * @param hook Hook the options are defined for. The hook will define which
 *        options are allowed.
 * @param raw_opts List of raw options formatted as @c KEY=VALUE , if @c NULL
 *        no option is defined.
 * @return 0 on success, or a negative errno value on error.
 */
int bf_hook_opts_init(struct bf_hook_opts *opts, enum bf_hook hook,
                      bf_list *raw_opts);

void bf_hook_opts_dump(const struct bf_hook_opts *opts, prefix_t *prefix,
                       enum bf_hook hook);
