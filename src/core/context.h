/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"

enum bf_hooks
{
    BF_HOOK_TC_INGRESS,
    BF_HOOK_IPT_PRE_ROUTING,
    BF_HOOK_IPT_LOCAL_IN,
    BF_HOOK_IPT_FORWARD,
    BF_HOOK_IPT_LOCAL_OUT,
    BF_HOOK_IPT_POST_ROUTING,
    BF_HOOK_TC_EGRESS,
    __BF_HOOK_MAX,
};

/**
 * @struct bf_context
 * @brief bpfilter working context. Only one context is used during the
 *  daemon's lifetime.
 *
 * @var bf_context::hooks
 *  Array containing a list of codegen for each hook. Each codegen represents
 *  a BPF program. A given front-end will have at most 1 codegen for each hook.
 */
struct bf_context
{
    bf_list hooks[__BF_HOOK_MAX];
};

/**
 * @brief Allocate and initialise a context.
 *
 * @param context Context to initialise. Can't be NULL.
 */
void bf_context_init(struct bf_context *context);

/**
 * @brief Clean up a context.
 *
 * @param context Context to clean up. Can't be NULL.
 */
void bf_context_clean(struct bf_context *context);

/**
 * @brief Convert a bpfilter hook to a string.
 *
 * If the value of @p hook is invalid, NULL is returned.
 *
 * @param hook The hook to convert
 * @return String representation of the hook, or NULL if the hook is invalid.
 */
const char *bf_hook_to_str(enum bf_hooks hook);
