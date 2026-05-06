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
 * Chain state is persisted in per-chain bpffs context maps and loaded on
 * demand by `bf_ctx_get_cgen()` and `bf_ctx_get_cgens()`; the global
 * context does not cache them.
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
 * @brief Unload all the existing chains.
 *
 * Equivalent to calling `bf_ctx_get_cgens` followed by
 * `bf_cgen_unload` on every entry.
 */
void bf_ctx_flush(void);

/**
 * @brief Load a codegen from bpffs by name.
 *
 * Opens `{bpffs}/bpfilter/{name}/` and deserializes the persisted context
 * map into a fresh `bf_cgen`. On success `*cgen` is set to a
 * newly-allocated codegen owned by the caller (use `_free_bf_cgen_`).
 *
 * @param name Name of the codegen to load. Can't be NULL.
 * @param cgen Output pointer to the loaded codegen. Can't be NULL. Left
 *        unchanged on failure.
 * @return 0 on success, `-ENOENT` if no chain exists with the given name,
 *         or another negative errno value on failure.
 */
int bf_ctx_get_cgen(const char *name, struct bf_cgen **cgen);

/**
 * @brief Discover and load all codegens persisted under `{bpffs}/bpfilter/`.
 *
 * The function allocates a new heap list with owning ops
 * (`bf_cgen_free`/`bf_cgen_pack`); on success the caller owns it and
 * must release it with `bf_list_free` (commonly via `_free_bf_list_`).
 * Per-entry deserialisation failures are logged and the offending chain
 * is skipped.
 *
 * @param cgens Output pointer to the allocated list. Can't be NULL.
 *        Must point to a `NULL` `bf_list *` on entry. Left unchanged on
 *        failure.
 * @return 0 on success, or a negative errno value on setup failure
 *         (cannot open pin directory, allocation failure).
 */
int bf_ctx_get_cgens(bf_list **cgens);

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
