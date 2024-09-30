/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include "core/dump.h"
#include "core/front.h"
#include "core/hook.h"

/**
 * @file ctx.h
 *
 * Global runtime context for @c bpfilter daemon.
 *
 * This file contains the definition of the @ref bf_ctx structure, which is 
 * the main structure used to store the daemon's runtime context.
 *
 * @ref bf_ctx can be serialized and deserialized, including all of its
 * fields. This way, bpfilter can be restarted without unloading the BPF
 * programs and maps.
 *
 * Like every other bf_* structure, most bf_* functions should expect a valid
 * pointer to a @ref bf_ctx structure. This is not exactly how it works
 * for @ref bf_ctx : public functions defined in this header do not require
 * any @ref bf_ctx , but those are only wrappers around private functions
 * defined in @c ctx.c , which do expect a valid pointer to a @ref bf_ctx .
 * This is done to prevent the user from creating and manipulating multiple
 * contexts, while keeping the API consistent with the other bf_* structures.
 */

struct bf_cgen;
struct bf_marsh;

/**
 * @struct bf_ctx
 *
 * bpfilter working context. Only one context is used during the daemon's
 * lifetime.
 */
struct bf_ctx
{
    /// Codegens used by bpfilter. One codegen per (hook, front) set.
    struct bf_cgen *cgens[_BF_HOOK_MAX][_BF_FRONT_MAX];
};

/**
 * Initialise the global bpfilter context.
 *
 * @return 0 on success, negative error code on failure.
 */
int bf_ctx_setup(void);

/**
 * Teardown the global bpfilter context.
 *
 * @param clear If true, all the BPF programs will be unloaded before clearing
 *        the context.
 */
void bf_ctx_teardown(bool clear);

/**
 * Dump content of the context.
 *
 * @param prefix Prefix to use for the dump.
 */
void bf_ctx_dump(prefix_t *prefix);

/**
 * Marshel the global bpfilter context.
 *
 * @param marsh @ref bf_marsh structure to fill with the marshalled context.
 * @return 0 on success, negative error code on failure.
 */
int bf_ctx_save(struct bf_marsh **marsh);

/**
 * Unmarshal the global bpfilter context.
 *
 * Once this function completes, the global context has been restored from the
 * marshalled context. On failure, the global context is left uninitialized.
 *
 * @param marsh @ref bf_marsh structure containing the marshalled context.
 * @return 0 on success, negative error code on failure.
 */
int bf_ctx_load(const struct bf_marsh *marsh);

/**
 * Get codegen for a given (hook, front) set.
 *
 * @param hook Hook to get the codegen from. Must be a valid hook.
 * @param front Front-end to get the codegen from. Must be a valid
 *        front-end.
 * @return The codegen for the given hook and front-end, or NULL if there is
 *         no such codegen.
 */
struct bf_cgen *bf_ctx_get_cgen(enum bf_hook hook, enum bf_front front);

/**
 * Delete a codegen from the context for a given (hook, front) set.
 *
 * If a corresponding codegen has been found, then it is removed from the
 * context and deleted. Otherwise the context remain unchanged.
 *
 * @param hook Hook to get the codegen from. Must be a valid hook.
 * @param front Front-end to get the codegen from. Must be a valid front-end.
 */
void bf_ctx_delete_cgen(enum bf_hook hook, enum bf_front front);

/**
 * Add a codegen to the context.
 *
 * @param hook Hook to add the codegen to. Must be a valid hook.
 * @param front Front-end to add the codegen to. Must be a valid front-end.
 * @param cgen Codegen to add to the context. Can't be NULL.
 * @return 0 on success, negative error code on failure. If a codegen already
 *         exists for the given (hook, front) set, then -EEXIST is returned.
 */
int bf_ctx_set_cgen(enum bf_hook hook, enum bf_front front,
                    struct bf_cgen *cgen);

/**
 * Replace the codegen for a given (hook, front) set, if any.
 *
 * If a codegen already exists for the given (hook, front) set, then it is
 * deleted and replaced by @p cgen. Otherwise, @p cgen is added to the
 * context.
 *
 * @param hook Hook to update the codegen for. Must be a valid hook.
 * @param front Front-end to update the codegen for. Must be a valid
 * @param cgen Codegen to update the context with. Can't be NULL.
 */
void bf_ctx_replace_cgen(enum bf_hook hook, enum bf_front front,
                         struct bf_cgen *cgen);
