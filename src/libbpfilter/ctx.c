/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/ctx.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/ctx.h>
#include <bpfilter/dump.h>
#include <bpfilter/elfstub.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

#include "cgen/cgen.h"
#include "core/lock.h"

/// Global runtime context. Populated by `bf_ctx_setup`; hidden in this TU.
static struct bf_ctx *_bf_global_ctx = NULL;

#define bf_ctx_default()                                                       \
    ((struct bf_ctx) {                                                         \
        .token_fd = -1,                                                        \
        .stubs = {0},                                                          \
        .with_bpf_token = false,                                               \
        .bpffs_path = NULL,                                                    \
        .verbose = 0,                                                          \
    })

static void _bf_ctx_cleanup(struct bf_ctx *ctx);

#define _clean_bf_ctx_ __attribute__((cleanup(_bf_ctx_cleanup)))

static int _bf_ctx_gen_token(const char *bpffs_path)
{
    _cleanup_close_ int mnt_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int token_fd = -1;

    mnt_fd = open(bpffs_path, O_DIRECTORY);
    if (mnt_fd < 0)
        return bf_err_r(errno, "failed to open '%s'", bpffs_path);

    bpffs_fd = openat(mnt_fd, ".", 0, O_RDWR);
    if (bpffs_fd < 0)
        return bf_err_r(errno, "failed to get bpffs FD from '%s'", bpffs_path);

    token_fd = bf_bpf_token_create(bpffs_fd);
    if (token_fd < 0) {
        return bf_err_r(token_fd, "failed to create BPF token for '%s'",
                        bpffs_path);
    }

    return TAKE_FD(token_fd);
}

/**
 * @brief Populate an empty context with the requested configuration.
 *
 * Performs the actual work (BTF load, BPF token creation, ELF stubs) on a
 * locally-owned stack `bf_ctx`, then atomically swaps the populated state
 * into `ctx` on success.
 *
 * @pre
 *  - `ctx` is not NULL and is in the `bf_ctx_default` state.
 *  - `bpffs_path` is not NULL.
 * @post
 *  - On success: `ctx` owns the BPF token (if requested), the ELF stubs,
 *    a heap copy of `bpffs_path`, and a vmlinux BTF reference.
 *  - On failure: `ctx` is unchanged.
 *
 * @param ctx Pre-allocated context to populate.
 * @param with_bpf_token If true, create a BPF token from bpffs.
 * @param bpffs_path Path to the bpffs mountpoint.
 * @param verbose Bitmask of verbose flags.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_ctx_init(struct bf_ctx *ctx, bool with_bpf_token,
                        const char *bpffs_path, uint16_t verbose)
{
    _clean_bf_ctx_ struct bf_ctx _ctx = bf_ctx_default();
    int r;

    assert(ctx);
    assert(bpffs_path);

    _ctx.with_bpf_token = with_bpf_token;
    _ctx.verbose = verbose;

    _ctx.bpffs_path = strdup(bpffs_path);
    if (!_ctx.bpffs_path)
        return -ENOMEM;

    if (_ctx.with_bpf_token) {
        _cleanup_close_ int token_fd = -1;

        r = bf_btf_kernel_has_token();
        if (r == -ENOENT) {
            return bf_err_r(
                r,
                "--with-bpf-token requested, but this kernel doesn't support BPF token");
        }
        if (r)
            return bf_err_r(r, "failed to check for BPF token support");

        token_fd = _bf_ctx_gen_token(_ctx.bpffs_path);
        if (token_fd < 0)
            return bf_err_r(token_fd, "failed to generate a BPF token");

        _ctx.token_fd = TAKE_FD(token_fd);
    }

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id) {
        r = bf_elfstub_new(&_ctx.stubs[id], id);
        if (r)
            return bf_err_r(r, "failed to create ELF stub ID %u", id);
    }

    bf_swap(*ctx, _ctx);

    return 0;
}

/**
 * @brief Release the resources owned by a context in place.
 *
 * Does not free the container. After the call, `ctx` is back to the
 * `bf_ctx_default()` state and may be safely re-initialised or cleaned-up again
 * (idempotent).
 *
 * @pre
 *  - `ctx` is not NULL.
 * @post
 *  - `ctx` is in the `bf_ctx_default` state.
 *
 * @param ctx Context to clean up.
 */
static void _bf_ctx_cleanup(struct bf_ctx *ctx)
{
    assert(ctx);

    closep(&ctx->token_fd);

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id)
        bf_elfstub_free(&ctx->stubs[id]);

    freep((void *)&ctx->bpffs_path);

    *ctx = bf_ctx_default();
}

int bf_ctx_new(struct bf_ctx **ctx, bool with_bpf_token, const char *bpffs_path,
               uint16_t verbose)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    assert(ctx);
    assert(bpffs_path);

    /* vmlinux BTF is a process-wide resource (single static in btf.c) but
     * its lifetime is currently coupled to the context. Pair setup/teardown
     * with the heap-owning constructor/destructor so the swap-style
     * _bf_ctx_init can run a cleanup on its local without tearing down the
     * BTF the live context will rely on. */
    r = bf_btf_setup();
    if (r)
        return bf_err_r(r, "failed to load vmlinux BTF");

    _ctx = malloc(sizeof(*_ctx));
    if (!_ctx) {
        bf_btf_teardown();
        return -ENOMEM;
    }

    *_ctx = bf_ctx_default();

    r = _bf_ctx_init(_ctx, with_bpf_token, bpffs_path, verbose);
    if (r) {
        bf_btf_teardown();
        return r;
    }

    *ctx = TAKE_PTR(_ctx);

    return 0;
}

void bf_ctx_free(struct bf_ctx **ctx)
{
    assert(ctx);

    if (!*ctx)
        return;

    _bf_ctx_cleanup(*ctx);
    bf_btf_teardown();
    freep((void *)ctx);
}

/**
 * See @ref bf_ctx_dump for details.
 */
static void _bf_ctx_dump(const struct bf_ctx *ctx, prefix_t *prefix)
{
    DUMP(prefix, "struct bf_ctx at %p", ctx);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "token_fd: %d", ctx->token_fd);

    bf_dump_prefix_pop(prefix);
}

static void _bf_free_dir(DIR **dir)
{
    if (!*dir)
        return;

    closedir(*dir);
    *dir = NULL;
}

#define _free_dir_ __attribute__((__cleanup__(_bf_free_dir)))

int bf_ctx_setup(bool with_bpf_token, const char *bpffs_path, uint16_t verbose)
{
    int r;

    r = bf_ctx_new(&_bf_global_ctx, with_bpf_token, bpffs_path, verbose);
    if (r)
        return bf_err_r(r, "failed to create new context");

    return 0;
}

void bf_ctx_teardown(void)
{
    bf_ctx_free(&_bf_global_ctx);
}

void bf_ctx_dump(prefix_t *prefix)
{
    if (!_bf_global_ctx)
        return;

    _bf_ctx_dump(_bf_global_ctx, prefix);
}

int bf_ctx_get_cgen(struct bf_lock *lock, struct bf_cgen **cgen)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    int r;

    assert(lock);
    assert(cgen);

    if (!_bf_global_ctx)
        return bf_err_r(-EINVAL, "context is not initialized");

    r = bf_cgen_new_from_dir_fd(&_cgen, lock);
    if (r)
        return bf_err_r(r, "failed to load chain '%s' from bpffs",
                        lock->chain_name ? lock->chain_name : "(unknown)");

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

int bf_ctx_get_cgens(struct bf_lock *lock, bf_list **cgens)
{
    _free_bf_list_ bf_list *_cgens = NULL;
    _free_dir_ DIR *dir = NULL;
    struct dirent *entry;
    int iter_fd;
    int r;

    assert(lock);
    assert(cgens);

    if (!_bf_global_ctx)
        return bf_err_r(-EINVAL, "context is not initialized");

    r = bf_list_new(&_cgens, &bf_list_ops_default(bf_cgen_free, bf_cgen_pack));
    if (r)
        return bf_err_r(r, "failed to allocate cgen list");

    /* fdopendir() takes ownership of the fd: dup so lock->pindir_fd remains
     * valid for further uses. */
    iter_fd = dup(lock->pindir_fd);
    if (iter_fd < 0)
        return bf_err_r(-errno, "failed to dup pin directory fd");

    dir = fdopendir(iter_fd);
    if (!dir) {
        r = -errno;
        close(iter_fd);
        return bf_err_r(r, "failed to open pin directory for iteration");
    }

    while (true) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;

        errno = 0;
        entry = readdir(dir);
        if (!entry && errno != 0) {
            bf_warn_r(errno, "readdir failed, returning partial results");
            break;
        }
        if (!entry)
            break;

        if (bf_streq(entry->d_name, ".") || bf_streq(entry->d_name, ".."))
            continue;

        if (entry->d_type != DT_DIR)
            continue;

        /* Skip in-flight staging directories owned by concurrent writers. */
        if (bf_strneq(entry->d_name, BF_LOCK_STAGING_PREFIX,
                      sizeof(BF_LOCK_STAGING_PREFIX) - 1))
            continue;

        r = bf_lock_acquire_chain(lock, entry->d_name, BF_LOCK_READ, false);
        if (r) {
            bf_warn_r(r, "failed to acquire READ lock on chain '%s', skipping",
                      entry->d_name);
            continue;
        }

        r = bf_cgen_new_from_dir_fd(&cgen, lock);
        if (r) {
            bf_warn_r(r, "failed to restore chain '%s', skipping",
                      entry->d_name);
            bf_lock_release_chain(lock);
            continue;
        }

        bf_lock_release_chain(lock);

        r = bf_list_push(_cgens, (void **)&cgen);
        if (r) {
            bf_warn_r(r, "failed to push chain '%s' to list, skipping",
                      entry->d_name);
            continue;
        }
    }

    *cgens = TAKE_PTR(_cgens);

    return 0;
}

int bf_ctx_token(void)
{
    if (!_bf_global_ctx)
        return -1;

    return _bf_global_ctx->token_fd;
}

const struct bf_elfstub *bf_ctx_get_elfstub(enum bf_elfstub_id id)
{
    if (!_bf_global_ctx)
        return NULL;

    return _bf_global_ctx->stubs[id];
}

bool bf_ctx_is_verbose(enum bf_verbose opt)
{
    if (!_bf_global_ctx)
        return false;

    return _bf_global_ctx->verbose & BF_FLAG(opt);
}

const char *bf_ctx_get_bpffs_path(void)
{
    if (!_bf_global_ctx)
        return NULL;

    return _bf_global_ctx->bpffs_path;
}
