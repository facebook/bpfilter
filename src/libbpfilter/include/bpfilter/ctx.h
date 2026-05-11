/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdbool.h>

#include <bpfilter/core/list.h>
#include <bpfilter/dump.h>

/**
 * @file ctx.h
 *
 * Runtime context for `bpfilter`.
 *
 * `struct bf_ctx` is an opaque, user-managed object obtained via
 * `bf_ctx_new()` and released via `bf_ctx_free()`. Each context carries
 * its own bpffs path, BPF token state, ELF stubs and vmlinux BTF, so
 * multiple contexts may coexist within a single process.
 *
 * Chain state is persisted in per-chain bpffs context maps and loaded on
 * demand by `bf_ctx_get_cgen()` and `bf_ctx_get_cgens()`; the context does
 * not cache them.
 */

struct bf_cgen;
struct bf_ctx;
struct bf_lock;

/**
 * @brief Allocate and initialise a new runtime context.
 *
 * On success, `*ctx` points to a freshly allocated context. The caller owns
 * the pointer and must release it with `bf_ctx_free()` (or via the
 * `_free_bf_ctx_` cleanup attribute). The context owns a heap copy of
 * `bpffs_path`; the caller may free or modify the input string after the
 * call returns.
 *
 * @pre
 *  - `ctx` is not NULL.
 *  - `bpffs_path` is not NULL.
 * @post
 *  - On success: `*ctx` points to a fully-initialised context.
 *  - On failure: `*ctx` is unchanged.
 *
 * @param ctx Output pointer to the new context.
 * @param with_bpf_token If true, create a BPF token from bpffs.
 * @param bpffs_path Path to the bpffs mountpoint.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_new(struct bf_ctx **ctx, bool with_bpf_token,
               const char *bpffs_path);

/**
 * @brief Free a runtime context.
 *
 * If `*ctx` is NULL, the call is a no-op.
 *
 * @pre
 *  - `ctx` is not NULL.
 * @post
 *  - `*ctx == NULL`.
 *
 * @param ctx Context to free.
 */
void bf_ctx_free(struct bf_ctx **ctx);

#define _free_bf_ctx_ __attribute__((cleanup(bf_ctx_free)))

/**
 * @brief Dump the runtime context.
 *
 * @param ctx Runtime context. Can't be NULL.
 * @param prefix Prefix to use for the dump.
 */
void bf_ctx_dump(const struct bf_ctx *ctx, prefix_t *prefix);

/**
 * @brief Load a codegen from a chain pinned in bpffs.
 *
 * Reads and deserializes the persisted context map from the chain
 * directory referenced by `lock` (the caller must have already acquired
 * the chain via `bf_lock_acquire_chain`). On success `*cgen` is set to
 * a newly-allocated codegen owned by the caller (use `_free_bf_cgen_`).
 *
 * @param ctx Runtime context the new codegen will hold a borrowed pointer
 *        to. Can't be NULL.
 * @param lock Lock providing the chain directory file descriptor. Must
 *        hold a valid `chain_fd`. Can't be NULL.
 * @param cgen Output pointer to the loaded codegen. Can't be NULL. Left
 *        unchanged on failure.
 * @return 0 on success, or a negative errno value on failure.
 */
int bf_ctx_get_cgen(const struct bf_ctx *ctx, struct bf_lock *lock,
                    struct bf_cgen **cgen);

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
 * @param ctx Runtime context the new codegens will hold a borrowed pointer
 *        to. Can't be NULL.
 * @param lock Lock that must already hold the pin directory locked
 *        (e.g. via `bf_lock_init(BF_LOCK_READ)` or `BF_LOCK_WRITE`).
 *        Must not currently hold a chain lock. Can't be NULL.
 * @param cgens Output pointer to the allocated list. Can't be NULL.
 *        Must point to a `NULL` `bf_list *` on entry. Left unchanged on
 *        failure.
 * @return 0 on success, or a negative errno value on setup failure
 *         (cannot open pin directory, allocation failure).
 */
int bf_ctx_get_cgens(const struct bf_ctx *ctx, struct bf_lock *lock,
                     bf_list **cgens);
