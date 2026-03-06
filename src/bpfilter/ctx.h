/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include <bpfilter/dump.h>
#include <bpfilter/list.h>

#include "cgen/elfstub.h"

/**
 * @file ctx.h
 *
 * Global runtime context for `bpfilter` daemon.
 *
 * This file contains the definition of the `bf_ctx` structure, which is
 * the main structure used to store the daemon's runtime context.
 *
 * All the public `bf_ctx_*` functions manipulate a private global context.
 * Chain state is persisted in per-chain bpffs context maps and restored
 * via `bf_ctx_setup` on restart.
 */

struct bf_cgen;
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
 * @brief Unload and delete all the codegens.
 */
void bf_ctx_flush(void);

/**
 * Get a codegen from the global context.
 *
 * @param name Name of the codegen to get. Can't be NULL.
 * @return The requested codegen, or NULL if not found.
 */
struct bf_cgen *bf_ctx_get_cgen(const char *name);

/**
 * Get the list of all @ref bf_cgen in the context.
 *
 * The @p cgens list returned to the caller does not own the codegens, it can
 * safely be cleaned up using @ref bf_list_clean or @ref bf_list_free .
 *
 * @param cgens List of @ref bf_cgen to fill. The list will be initialised by
 *        this function. Can't be NULL. On failure, @p cgens is left unchanged.
 * @return 0 on success, or negative errno value on failure.
 */
int bf_ctx_get_cgens(bf_list *cgens);

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

/**
 * @brief Get a ELF stub from its ID.
 *
 * @param id ID of the ELF stub to retrieve.
 * @return The requested ELF stub.
 */
const struct bf_elfstub *bf_ctx_get_elfstub(enum bf_elfstub_id id);
