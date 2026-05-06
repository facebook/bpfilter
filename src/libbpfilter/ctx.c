/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
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

#define _free_bf_ctx_ __attribute__((cleanup(_bf_ctx_free)))

/**
 * @struct bf_ctx
 *
 * bpfilter working context. Only one context is used during the library's
 * lifetime.
 */
struct bf_ctx
{
    /// BPF token file descriptor
    int token_fd;

    int lock_fd;

    struct bf_elfstub *stubs[_BF_ELFSTUB_MAX];

    /// Pass a token to BPF system calls, obtained from bpffs.
    bool with_bpf_token;

    /// Path to the bpffs to pin the BPF objects into.
    const char *bpffs_path;

    /// Verbose flags.
    uint16_t verbose;
};

static void _bf_ctx_free(struct bf_ctx **ctx);

/// Global runtime context. Hidden in this translation unit.
static struct bf_ctx *_bf_global_ctx = NULL;

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
 * Create and initialize a new context.
 *
 * On failure, @p ctx is left unchanged.
 *
 * @param ctx New context to create. Can't be NULL.
 * @param with_bpf_token If true, create a BPF token from bpffs.
 * @param bpffs_path Path to the bpffs mountpoint. Can't be NULL.
 * @param verbose Bitmask of verbose flags.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_ctx_new(struct bf_ctx **ctx, bool with_bpf_token,
                       const char *bpffs_path, uint16_t verbose)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    assert(ctx);
    assert(bpffs_path);

    _ctx = calloc(1, sizeof(*_ctx));
    if (!_ctx)
        return -ENOMEM;

    r = bf_btf_setup();
    if (r)
        return bf_err_r(r, "failed to load vmlinux BTF");

    _ctx->with_bpf_token = with_bpf_token;
    _ctx->bpffs_path = bpffs_path;
    _ctx->verbose = verbose;
    _ctx->lock_fd = -1;

    _ctx->token_fd = -1;
    if (_ctx->with_bpf_token) {
        _cleanup_close_ int token_fd = -1;

        r = bf_btf_kernel_has_token();
        if (r == -ENOENT) {
            bf_err(
                "--with-bpf-token requested, but this kernel doesn't support BPF token");
            return r;
        }
        if (r)
            return bf_err_r(r, "failed to check for BPF token support");

        token_fd = _bf_ctx_gen_token(_ctx->bpffs_path);
        if (token_fd < 0)
            return bf_err_r(token_fd, "failed to generate a BPF token");

        _ctx->token_fd = TAKE_FD(token_fd);
    }

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id) {
        r = bf_elfstub_new(&_ctx->stubs[id], id);
        if (r)
            return bf_err_r(r, "failed to create ELF stub ID %u", id);
    }

    *ctx = TAKE_PTR(_ctx);

    return 0;
}

/**
 * Free a context.
 *
 * If @p ctx points to a NULL pointer, this function does nothing. Once
 * the function returns, @p ctx points to a NULL pointer.
 *
 * @param ctx Context to free. Can't be NULL.
 */
static void _bf_ctx_free(struct bf_ctx **ctx)
{
    assert(ctx);

    if (!*ctx)
        return;

    closep(&(*ctx)->token_fd);
    closep(&(*ctx)->lock_fd);

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id)
        bf_elfstub_free(&(*ctx)->stubs[id]);

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
    _cleanup_close_ int pindir_fd = -1;
    int r;

    r = _bf_ctx_new(&_bf_global_ctx, with_bpf_token, bpffs_path, verbose);
    if (r)
        return bf_err_r(r, "failed to create new context");

    pindir_fd = bf_ctx_get_pindir_fd();
    if (pindir_fd < 0) {
        _bf_ctx_free(&_bf_global_ctx);
        return bf_err_r(pindir_fd, "failed to get pin directory FD");
    }

    r = flock(pindir_fd, LOCK_EX | LOCK_NB);
    if (r) {
        _bf_ctx_free(&_bf_global_ctx);
        return bf_err_r(-errno, "failed to lock pin directory");
    }

    _bf_global_ctx->lock_fd = TAKE_FD(pindir_fd);

    return 0;
}

void bf_ctx_teardown(void)
{
    _bf_ctx_free(&_bf_global_ctx);
}

void bf_ctx_flush(void)
{
    _free_bf_list_ bf_list *cgens = NULL;
    int r;

    if (!_bf_global_ctx)
        return;

    r = bf_ctx_get_cgens(&cgens);
    if (r) {
        bf_warn_r(r, "failed to discover chains during flush");
        return;
    }

    bf_list_foreach (cgens, cgen_node)
        bf_cgen_unload(bf_list_node_get_data(cgen_node));
}

void bf_ctx_dump(prefix_t *prefix)
{
    if (!_bf_global_ctx)
        return;

    _bf_ctx_dump(_bf_global_ctx, prefix);
}

int bf_ctx_get_cgen(const char *name, struct bf_cgen **cgen)
{
    _free_bf_cgen_ struct bf_cgen *_cgen = NULL;
    _cleanup_close_ int pindir_fd = -1;
    _cleanup_close_ int chain_fd = -1;
    int r;

    assert(name);
    assert(cgen);

    if (!_bf_global_ctx)
        return bf_err_r(-EINVAL, "context is not initialized");

    pindir_fd = bf_ctx_get_pindir_fd();
    if (pindir_fd < 0)
        return pindir_fd;

    chain_fd = bf_opendir_at(pindir_fd, name, false);
    if (chain_fd < 0)
        return chain_fd;

    r = bf_cgen_new_from_dir_fd(&_cgen, chain_fd);
    if (r)
        return bf_err_r(r, "failed to load chain '%s' from bpffs", name);

    *cgen = TAKE_PTR(_cgen);

    return 0;
}

int bf_ctx_get_cgens(bf_list **cgens)
{
    _free_bf_list_ bf_list *_cgens = NULL;
    _cleanup_close_ int pindir_fd = -1;
    _free_dir_ DIR *dir = NULL;
    struct dirent *entry;
    int iter_fd;
    int r;

    assert(cgens);

    if (!_bf_global_ctx)
        return bf_err_r(-EINVAL, "context is not initialized");

    r = bf_list_new(&_cgens, &bf_list_ops_default(bf_cgen_free, bf_cgen_pack));
    if (r)
        return bf_err_r(r, "failed to allocate cgen list");

    pindir_fd = bf_ctx_get_pindir_fd();
    if (pindir_fd < 0)
        return bf_err_r(pindir_fd, "failed to get pin directory FD");

    /* fdopendir() takes ownership of the fd: dup so pindir_fd remains valid
     * for openat() calls inside the loop. */
    iter_fd = dup(pindir_fd);
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
        _cleanup_close_ int chain_fd = -1;

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

        chain_fd = openat(pindir_fd, entry->d_name, O_DIRECTORY);
        if (chain_fd < 0) {
            bf_warn_r(errno, "failed to open chain directory '%s', skipping",
                      entry->d_name);
            continue;
        }

        r = bf_cgen_new_from_dir_fd(&cgen, chain_fd);
        if (r) {
            bf_warn_r(r, "failed to restore chain '%s', skipping",
                      entry->d_name);
            continue;
        }

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

int bf_ctx_get_pindir_fd(void)
{
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int pindir_fd = -1;

    if (!_bf_global_ctx)
        return bf_err_r(-EINVAL, "context is not initialized");

    bpffs_fd = bf_opendir(_bf_global_ctx->bpffs_path);
    if (bpffs_fd < 0) {
        return bf_err_r(bpffs_fd, "failed to open bpffs at %s",
                        _bf_global_ctx->bpffs_path);
    }

    pindir_fd = bf_opendir_at(bpffs_fd, "bpfilter", true);
    if (pindir_fd < 0) {
        return bf_err_r(pindir_fd, "failed to open pin directory %s/bpfilter",
                        _bf_global_ctx->bpffs_path);
    }

    return TAKE_FD(pindir_fd);
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
    return _bf_global_ctx->bpffs_path;
}
