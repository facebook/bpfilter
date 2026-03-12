/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <bpfilter/core/list.h>
#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>

/**
 * @file ctx.h
 *
 * Global runtime context for `bpfilter`.
 *
 * This file contains the definition of the `bf_ctx` structure, which is
 * the main structure used to store the runtime context.
 *
 * All the public `bf_ctx_*` functions manipulate a private global context.
 * Chain state is persisted in per-chain bpffs context maps and restored
 * via `bf_ctx_setup` on restart.
 */

struct bf_cgen;

enum bf_verbose
{
    BF_VERBOSE_DEBUG,
    BF_VERBOSE_BPF,
    BF_VERBOSE_BYTECODE,
    _BF_VERBOSE_MAX,
};

/**
 * Initialise the global context.
 *
 * @param with_bpf_token If true, create a BPF token from bpffs.
 * @param bpffs_path Path to the bpffs mountpoint. Can't be NULL.
 * @param verbose Bitmask of verbose flags.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_setup(bool with_bpf_token, const char *bpffs_path, uint16_t verbose);

/**
 * Teardown the global context.
 */
void bf_ctx_teardown(void);

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
 * @brief Get a ELF stub from its ID.
 *
 * @param id ID of the ELF stub to retrieve.
 * @return The requested ELF stub.
 */
const struct bf_elfstub *bf_ctx_get_elfstub(enum bf_elfstub_id id);

/**
 * @return true if the given verbose flag is set.
 */
bool bf_ctx_is_verbose(enum bf_verbose opt);
