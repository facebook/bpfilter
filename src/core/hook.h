/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/flavor.h"

/**
 * @file hook.h
 *
 * bpfilter's BPF programs are attached to hooks in the kernel. This file
 * contains the definitions for the hooks we support.
 */

enum bf_hook
{
    BF_HOOK_TC_INGRESS,
    BF_HOOK_IPT_PRE_ROUTING,
    BF_HOOK_IPT_LOCAL_IN,
    BF_HOOK_IPT_FORWARD,
    BF_HOOK_IPT_LOCAL_OUT,
    BF_HOOK_IPT_POST_ROUTING,
    BF_HOOK_TC_EGRESS,
    _BF_HOOK_MAX,
};

/**
 * @brief Convert a bpfilter hook to a string.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return String representation of the hook.
 */
const char *bf_hook_to_str(enum bf_hook hook);

/**
 * @brief Convert a bpfilter hook to a BPF program type.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The BPF program type corresponding to @p hook.
 */
unsigned int bf_hook_to_bpf_prog_type(enum bf_hook hook);

/**
 * @brief Get the expected flavor for a given hook.
 *
 * @param hook BPF hook. Must be valid.
 * @return bpfilter flavor corresponding to @p hook.
 */
enum bf_flavor bf_hook_to_flavor(enum bf_hook hook);

/**
 * @brief Convert a bpfilter hook to a BPF attach type.
 *
 * @param hook The hook to convert. Must be a valid hook.
 * @return The BPF attach type corresponding to @p hook.
 */
enum bpf_attach_type bf_hook_to_attach_type(enum bf_hook hook);
