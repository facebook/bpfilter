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
struct bf_lock;

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
 * Only one global context may exist at a time. Calling `bf_ctx_setup` while
 * a context is already initialised returns `-EBUSY` and leaves the existing
 * context untouched; the caller must `bf_ctx_teardown` first to re-initialise.
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
 * @brief Load a codegen from a chain pinned in bpffs.
 *
 * Reads and deserializes the persisted context map from the chain
 * directory referenced by `lock` (the caller must have already acquired
 * the chain via `bf_lock_acquire_chain`). On success `*cgen` is set to
 * a newly-allocated codegen owned by the caller (use `_free_bf_cgen_`).
 *
 * @param lock Lock providing the chain directory file descriptor. Must
 *        hold a valid `chain_fd`. Can't be NULL.
 * @param cgen Output pointer to the loaded codegen. Can't be NULL. Left
 *        unchanged on failure.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_get_cgen(struct bf_lock *lock, struct bf_cgen **cgen);

/**
 * @brief Discover and load all codegens persisted under `{bpffs}/bpfilter/`.
 *
 * The function allocates a new heap list with owning ops
 * (`bf_cgen_free`/`bf_cgen_pack`); on success the caller owns it and
 * must release it with `bf_list_free` (commonly via `_free_bf_list_`).
 * For each chain entry it acquires a `BF_LOCK_READ` chain lock via
 * `bf_lock_acquire_chain` for the duration of the deserialise step,
 * then releases it before moving to the next chain. Per-entry failures
 * are logged and the offending chain is skipped.
 *
 * @param lock Lock that must already hold the pin directory locked
 *        (e.g. via `bf_lock_init(BF_LOCK_READ)` or `BF_LOCK_WRITE`).
 *        Must not currently hold a chain lock. Can't be NULL.
 * @param cgens Output pointer to the allocated list. Can't be NULL.
 *        Must point to a `NULL` `bf_list *` on entry. Left unchanged on
 *        failure.
 * @return 0 on success, or a negative errno value on setup failure
 *         (cannot open pin directory, allocation failure).
 */
int bf_ctx_get_cgens(struct bf_lock *lock, bf_list **cgens);

/**
 * Get the BPF token file descriptor.
 *
 * @return The BPF token file descriptor, or -1 if no token is used.
 */
int bf_ctx_token(void);

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

/**
 * @return Path to the configured BPF filesystem.
 */
const char *bf_ctx_get_bpffs_path(void);
