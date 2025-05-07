/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include "core/dump.h"
#include "core/front.h"
#include "core/hook.h"
#include "core/list.h"

/**
 * @file ctx.h
 *
 * Global runtime context for @c bpfilter daemon.
 *
 * This file contains the definition of the @ref bf_ctx structure, which is
 * the main structure used to store the daemon's runtime context.
 *
 * All the public @c bf_ctx_* functions manipulate a private global context.
 * This context can be serialized and deserialized to restore the daemon's
 * runtime context if bpfilter is restarted.
 *
 * The @c bf_ctx structure contains an array of lists containing the codegens.
 * There is a list of codegen for each hook. Some hooks allow for multiple
 * codegens to be defined (e.g. XDP, TC), but others do not
 * (e.g. BF_HOOK_NF_LOCAL_IN) in which case the list contains a single codegen.
 */

struct bf_cgen;
struct bf_marsh;
struct bf_ns;

/**
 * Initialise the global context.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_setup(void);

/**
 * Teardown the global context.
 *
 * If @ref bf_ctx_save has not been called prior to this function, the runtime
 * context will be lost: if bpfilter is stopped and @c clear is false, bpfilter
 * will lost track of its BPF objects.
 *
 * @param clear If true, all the BPF programs will be unloaded before clearing
 *        the context.
 */
void bf_ctx_teardown(bool clear);

/**
 * Dump the global context.
 *
 * @param prefix Prefix to use for the dump.
 */
void bf_ctx_dump(prefix_t *prefix);

/**
 * Serialize the global context.
 *
 * @param marsh On succes, contains the serialized global context. Unchanged
 *        on failure. Can't be NULL. The owner owns the allocated memory.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_save(struct bf_marsh **marsh);

/**
 * Deserialize the global context.
 *
 * @param marsh Serialized global context to restore. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_load(const struct bf_marsh *marsh);

/**
 * Unload and delete all the codegens, reset the context to a clean state.
 *
 * On failure, the context is left unchanged.
 *
 * @param front Front to flush the codegens for.
 */
void bf_ctx_flush(enum bf_front front);

/**
 * Check if the context is empty (no codegen defined).
 *
 * @return true is the context is empty, false otherwise.
 */
bool bf_ctx_is_empty(void);

/**
 * Get a codegen from the global context.
 *
 * @param name Name of the codegen to get. Can't be NULL.
 * @return The requested codegen, or NULL if not found.
 */
struct bf_cgen *bf_ctx_get_cgen(const char *name);

/**
 * Get the list of @ref bf_cgen defined for a given @p front .
 *
 * The @p cgens list returned to the caller does not own the codegens, it can
 * safely be cleaned up using @ref bf_list_clean or @ref bf_list_free .
 *
 * @param cgens List of @ref bf_cgen to fill. The list will be initialised by
 *        this function. Can't be NULL. On failure, @p cgens is left unchanged.
 * @param front Front the get the list of @ref bf_cgen for.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_ctx_get_cgens_for_front(bf_list *cgens, enum bf_front front);

/**
 * Add a codegen to the global context.
 *
 * @param cgen Codegen to add to the context. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure. If a chain
 *         already exist in the context with the same name, the codegen is not
 *         added to the context and `-EEXIST` is returned.
 */
int bf_ctx_set_cgen(struct bf_cgen *cgen);

/**
 * Delete a codegen from the context.
 *
 * @param cgen Codegen to delete from the context. The codegen will be freed.
 *        Can't be NULL.
 * @param unload Unload the codegen from the system before deleting it.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_ctx_delete_cgen(struct bf_cgen *cgen, bool unload);

/**
 * Get the daemon's original namespaces.
 *
 * During the creation of the global context, the daemon will open a reference
 * to its namespaces. This is required to jump a a client's namespace on request
 * and come back to the original namespace afterward. This function returns a
 * pointer to the `bf_ns` object referencing the original namespaces.
 *
 * @return A `bf_ns` object pointer.
 */
struct bf_ns *bf_ctx_get_ns(void);

/**
 * Get the BPF token file descriptor.
 *
 * @return The BPF token file descriptor, or -1 if no token is used.
 */
int bf_ctx_token(void);

/**
 * @brief Return a file descriptor to bpfilter's pin directory.
 *
 * @return File descriptor to bpfilter's pin directory, or a negative errno
 *         value on failure.
 */
int bf_ctx_get_pindir_fd(void);

/**
 * @brief Remove the pin directory.
 *
 * If the pin directory can't be removed, an error is printed. However, if it's
 * due to the directory not being empty, or not existing, no error is printed,
 * but the errno value is returned anyway. The called will know how to deal with
 * this situation.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_rm_pindir(void);
