/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "core/dump.h"
#include "core/hook.h"
#include "core/list.h"
#include "shared/front.h"

/**
 * @file context.h
 *
 * bpfilter runtime context. This file contains the definition of the
 * @ref bf_context structure, which is the main structure used to store the
 * daemon's runtime context.
 *
 * @ref bf_context can be serialized and deserialized, including all of its
 * fields. This way, bpfilter can be restarted without unloading the BPF
 * programs and maps.
 *
 * Like every other bf_* structure, most bf_* functions should expect a valid
 * pointer to a @ref bf_context structure. This is not exactly how it works
 * for @ref bf_context: public functions defined in this header do not require
 * any @ref bf_context, but those are only wrappers around private functions
 * defined in context.c, which do expect a valid pointer to a @ref bf_context.
 * This is done to prevent the user from creating and manipulating multiple
 * contexts, while keeping the API consistent with the other bf_* structures.
 */

struct bf_codegen;
struct bf_marsh;

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
    bf_list hooks[_BF_HOOK_MAX];
};

/**
 * @brief Initialise the global bpfilter context.
 *
 * @return 0 on success, negative error code on failure.
 */
int bf_context_setup(void);

/**
 * @brief Teardown the global bpfilter context.
 *
 * @param clear If true, all the BPF programs will be unloaded before clearing
 * the context.
 */
void bf_context_teardown(bool clear);

/**
 * @brief Dump content of the context.
 * @param prefix Prefix to use for the dump.
 */
void bf_context_dump(prefix_t *prefix);

/**
 * @brief Marshel the global bpfilter context.
 *
 * @param marsh @ref bf_marsh structure to fill with the marshalled context.
 * @return 0 on success, negative error code on failure.
 */
int bf_context_save(struct bf_marsh **marsh);

/**
 * @brief Unmarshal the global bpfilter context.
 *
 * Once this function completes, the global context has been restored from the
 * marshalled context. On failure, the global context is left uninitialized.
 *
 * @param marsh @ref bf_marsh structure containing the marshalled context.
 * @return 0 on success, negative error code on failure.
 */
int bf_context_load(const struct bf_marsh *marsh);

/**
 * @brief Iterate over all codegens.
 *
 * @param codegen Name to use to store the current codegen in.
 */
#define bf_context_foreach_codegen(codegen)                                    \
    for (struct bf_codegen *_i = NULL, *codegen = NULL;                        \
         (codegen = bf_context_get_next_codegen((const void **)&_i));)

/**
 * @brief Iterate over codegens for a given hook.
 *
 * @param codegen Name to use to store the current codegen in.
 * @param hook Hook to iterate over.
 */
#define bf_context_foreach_codegen_by_hook(codegen, hook)                      \
    for (struct bf_codegen *_i = NULL, *codegen = NULL;                        \
         (codegen = bf_context_get_next_codegen_by_hook((const void **)&_i,    \
                                                        (hook)));)

/**
 * @brief Iterate over codegens for a given front-end.
 *
 * @param codegen Name to use to store the current codegen in.
 * @param fe Front-end to iterate over.
 */
#define bf_context_foreach_codegen_by_fe(codegen, fe)                          \
    for (struct bf_codegen *_i = NULL, *codegen = NULL;                        \
         (codegen =                                                            \
              bf_context_get_next_codegen_by_fe((const void **)&_i, (fe)));)

/**
 * @brief Get codegen for a given (hook, front) set.
 *
 * @param hook Hook to get the codegen from. Must be a valid hook.
 * @param front Front-end to get the codegen from. Must be a valid
 * front-end.
 * @return The codegen for the given hook and front-end, or NULL if there is
 * no such codegen.
 */
struct bf_codegen *bf_context_get_codegen(enum bf_hook hook,
                                          enum bf_front front);

/**
 * @brief Take a codegen out of the context for a given (hook, front) set.
 *
 * The codegen returned must then be freed by the caller. It's not part of
 * the context anymore.
 *
 * @param hook Hook to get the codegen from. Must be a valid hook.
 * @param front Front-end to get the codegen from. Must be a valid front-end.
 * @return The codegen for the given hook and front-end, or NULL if there is no
 * such codegen.
 */
struct bf_codegen *bf_context_take_codegen(enum bf_hook hook,
                                           enum bf_front front);

/**
 * @brief Delete a codegen from the context for a given (hook, front) set.
 *
 * If a corresponding codegen has been found, then it is removed from the
 * context and deleted. Otherwise the context remain unchanged.
 *
 * @param hook Hook to get the codegen from. Must be a valid hook.
 * @param front Front-end to get the codegen from. Must be a valid front-end.
 */
void bf_context_delete_codegen(enum bf_hook hook, enum bf_front front);

/**
 * @brief Add a codegen to the context.
 *
 * @param hook Hook to add the codegen to. Must be a valid hook.
 * @param front Front-end to add the codegen to. Must be a valid front-end.
 * @param codegen Codegen to add to the context. Can't be NULL.
 * @return 0 on success, negative error code on failure. If a codegen already
 *  exists for the given (hook, front) set, then -EEXIST is returned.
 */
int bf_context_set_codegen(enum bf_hook hook, enum bf_front front,
                           struct bf_codegen *codegen);

/**
 * @brief Update the codegen for a given (hook, front) set.
 *
 * If a codegen already exists for the given (hook, front) set, then it is
 * deleted and replaced by @p codegen. Otherwise, @p codegen is added to the
 * context.
 *
 * @param hook Hook to update the codegen for. Must be a valid hook.
 * @param front Front-end to update the codegen for. Must be a valid
 * @param codegen Codegen to update the context with. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_context_update_codegen(enum bf_hook hook, enum bf_front front,
                              struct bf_codegen *codegen);

/**
 * @brief Iterate over all codegens.
 *
 * @param iter Opaque iterator. Pointer to a void * variable. If *iter is NULL,
 * then the first codegen is returned. Otherwise, the next codegen is returned.
 * @return The next codegen, or NULL if there is no more.
 */
struct bf_codegen *bf_context_get_next_codegen(const void **iter);

/**
 * @brief Iterate over all codegens for a given hook.
 *
 * @param iter Opaque iterator. Pointer to a void * variable. If *iter is NULL,
 * then the first codegen is returned. Otherwise, the next codegen is returned.
 * @return The next codegen, or NULL if there is no more.
 */
struct bf_codegen *bf_context_get_next_codegen_by_hook(const void **iter,
                                                       enum bf_hook hook);

/**
 * @brief Iterate over all codegens for a given front-end.
 *
 * @param iter Opaque iterator. Pointer to a void * variable. If *iter is NULL,
 * then the first codegen is returned. Otherwise, the next codegen is returned.
 * @return The next codegen, or NULL if there is no more.
 */
struct bf_codegen *bf_context_get_next_codegen_by_fe(const void **iter,
                                                     enum bf_front front);
