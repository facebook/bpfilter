/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "ctx.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/btf.h>
#include <bpfilter/chain.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/io.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/ns.h>
#include <bpfilter/pack.h>

#include "cgen/cgen.h"
#include "cgen/elfstub.h"
#include "opts.h"

#define _free_bf_ctx_ __attribute__((cleanup(_bf_ctx_free)))

/**
 * @struct bf_ctx
 *
 * bpfilter working context. Only one context is used during the daemon's
 * lifetime.
 */
struct bf_ctx
{
    /// Namespaces the daemon was started in.
    struct bf_ns ns;

    /// BPF token file descriptor
    int token_fd;

    bf_list cgens;

    struct bf_elfstub *stubs[_BF_ELFSTUB_MAX];
};

static void _bf_ctx_free(struct bf_ctx **ctx);

/// Global daemon context. Hidden in this translation unit.
static struct bf_ctx *_bf_global_ctx = NULL;

static int _bf_ctx_gen_token(void)
{
    _cleanup_close_ int mnt_fd = -1;
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int token_fd = -1;

    mnt_fd = open(bf_opts_bpffs_path(), O_DIRECTORY);
    if (mnt_fd < 0)
        return bf_err_r(errno, "failed to open '%s'", bf_opts_bpffs_path());

    bpffs_fd = openat(mnt_fd, ".", 0, O_RDWR);
    if (bpffs_fd < 0)
        return bf_err_r(errno, "failed to get bpffs FD from '%s'",
                        bf_opts_bpffs_path());

    token_fd = bf_bpf_token_create(bpffs_fd);
    if (token_fd < 0) {
        return bf_err_r(token_fd, "failed to create BPF token for '%s'",
                        bf_opts_bpffs_path());
    }

    return TAKE_FD(token_fd);
}

/**
 * Create and initialize a new context.
 *
 * On failure, @p ctx is left unchanged.
 *
 * @param ctx New context to create. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_ctx_new(struct bf_ctx **ctx)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    assert(ctx);

    _ctx = calloc(1, sizeof(*_ctx));
    if (!_ctx)
        return -ENOMEM;

    r = bf_ns_init(&_ctx->ns, getpid());
    if (r)
        return bf_err_r(r, "failed to initialise current bf_ns");

    _ctx->token_fd = -1;
    if (bf_opts_with_bpf_token()) {
        _cleanup_close_ int token_fd = -1;

        r = bf_btf_kernel_has_token();
        if (r == -ENOENT) {
            bf_err(
                "--with-bpf-token requested, but this kernel doesn't support BPF token");
            return r;
        }
        if (r)
            return bf_err_r(r, "failed to check for BPF token support");

        token_fd = _bf_ctx_gen_token();
        if (token_fd < 0)
            return bf_err_r(token_fd, "failed to generate a BPF token");

        _ctx->token_fd = TAKE_FD(token_fd);
    }

    _ctx->cgens = bf_list_default(bf_cgen_free, bf_cgen_pack);

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

    bf_ns_clean(&(*ctx)->ns);
    closep(&(*ctx)->token_fd);
    bf_list_clean(&(*ctx)->cgens);

    for (enum bf_elfstub_id id = 0; id < _BF_ELFSTUB_MAX; ++id)
        bf_elfstub_free(&(*ctx)->stubs[id]);

    freep((void *)ctx);
}

/**
 * See @ref bf_ctx_dump for details.
 */
static void _bf_ctx_dump(const struct bf_ctx *ctx, prefix_t *prefix)
{
    DUMP(prefix, "struct bf_ctx at %p", ctx);

    bf_dump_prefix_push(prefix);

    // Namespaces
    DUMP(prefix, "ns: struct bf_ns")
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "net: struct bf_ns_info");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "fd: %d", ctx->ns.net.fd);
    DUMP(bf_dump_prefix_last(prefix), "inode: %u", ctx->ns.net.inode);
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "mnt: struct bf_ns_info");
    bf_dump_prefix_push(prefix);
    DUMP(prefix, "fd: %d", ctx->ns.mnt.fd);
    DUMP(bf_dump_prefix_last(prefix), "inode: %u", ctx->ns.mnt.inode);
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "token_fd: %d", ctx->token_fd);

    // Codegens
    DUMP(bf_dump_prefix_last(prefix), "cgens: bf_list<struct bf_cgen>[%lu]",
         bf_list_size(&ctx->cgens));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (bf_list_is_tail(&ctx->cgens, cgen_node))
            bf_dump_prefix_last(prefix);

        bf_cgen_dump(cgen, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

/**
 * See @ref bf_ctx_get_cgen for details.
 */
static struct bf_cgen *_bf_ctx_get_cgen(const struct bf_ctx *ctx,
                                        const char *name)
{
    assert(ctx);
    assert(name);

    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (bf_streq(cgen->chain->name, name))
            return cgen;
    }

    return NULL;
}

/**
 * See @ref bf_ctx_get_cgens for details.
 */
static int _bf_ctx_get_cgens(const struct bf_ctx *ctx, bf_list *cgens)
{
    _clean_bf_list_ bf_list _cgens = bf_list_default_from(*cgens);
    int r;

    assert(ctx);
    assert(cgens);

    bf_list_foreach (&ctx->cgens, cgen_node) {
        r = bf_list_add_tail(&_cgens, bf_list_node_get_data(cgen_node));
        if (r)
            return r;
    }

    *cgens = bf_list_move(_cgens);

    return 0;
}

/**
 * See @ref bf_ctx_set_cgen for details.
 */
static int _bf_ctx_set_cgen(struct bf_ctx *ctx, struct bf_cgen *cgen)
{
    assert(ctx);
    assert(cgen);

    if (_bf_ctx_get_cgen(ctx, cgen->chain->name))
        return bf_err_r(-EEXIST, "codegen already exists in context");

    return bf_list_add_tail(&ctx->cgens, cgen);
}

static int _bf_ctx_delete_cgen(struct bf_ctx *ctx, struct bf_cgen *cgen,
                               bool unload)
{
    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *_cgen = bf_list_node_get_data(cgen_node);

        if (_cgen != cgen)
            continue;

        if (unload)
            bf_cgen_unload(_cgen);

        bf_list_delete(&ctx->cgens, cgen_node);

        return 0;
    }

    return -ENOENT;
}

static void _bf_free_dir(DIR **dir)
{
    if (!*dir)
        return;

    closedir(*dir);
    *dir = NULL;
}

#define _free_dir_ __attribute__((__cleanup__(_bf_free_dir)))

/**
 * @brief Discover and restore chains from bpffs context maps.
 *
 * Iterates subdirectories under `{bpffs}/bpfilter/`, deserializing each
 * chain's `bf_ctx` context map into a `bf_cgen` and adding it to the
 * global context. The global context must already be initialized via
 * `bf_ctx_setup` before calling this function.
 *
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_ctx_discover(void)
{
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int pindir_fd = -1;
    _free_dir_ DIR *dir = NULL;
    struct dirent *entry;
    int iter_fd;
    int r;

    bpffs_fd = bf_opendir(bf_opts_bpffs_path());
    if (bpffs_fd < 0) {
        return bf_err_r(bpffs_fd, "failed to open bpffs at %s",
                        bf_opts_bpffs_path());
    }

    pindir_fd = bf_opendir_at(bpffs_fd, "bpfilter", false);
    if (pindir_fd < 0) {
        if (pindir_fd == -ENOENT) {
            bf_info("no bpfilter pin directory found, nothing to discover");
            return 0;
        }
        return bf_err_r(pindir_fd, "failed to open pin directory");
    }

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

    for (;;) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;
        _cleanup_close_ int chain_fd = -1;

        errno = 0;
        entry = readdir(dir);
        if (!entry)
            break;

        if (bf_streq(entry->d_name, ".") || bf_streq(entry->d_name, ".."))
            continue;

        if (entry->d_type != DT_DIR)
            continue;

        chain_fd = openat(pindir_fd, entry->d_name, O_DIRECTORY);
        if (chain_fd < 0) {
            bf_warn("failed to open chain directory '%s', skipping",
                    entry->d_name);
            continue;
        }

        r = bf_cgen_new_from_dir_fd(&cgen, chain_fd);
        if (r) {
            bf_warn("failed to restore chain '%s', skipping", entry->d_name);
            continue;
        }

        bf_info("discovered chain '%s'", entry->d_name);

        r = bf_list_push(&_bf_global_ctx->cgens, (void **)&cgen);
        if (r) {
            bf_warn("failed to add restored chain '%s' to context, skipping",
                    entry->d_name);
        }
    }

    if (errno)
        return bf_err_r(-errno, "failed to read pin directory");

    return 0;
}

int bf_ctx_setup(void)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    r = _bf_ctx_new(&_ctx);
    if (r)
        return bf_err_r(r, "failed to create new context");

    _bf_global_ctx = TAKE_PTR(_ctx);

    if (!bf_opts_transient()) {
        r = _bf_ctx_discover();
        if (r) {
            _bf_ctx_free(&_bf_global_ctx);
            return bf_err_r(r, "failed to discover chains");
        }
    }

    return 0;
}

void bf_ctx_teardown(bool clear)
{
    if (clear) {
        bf_list_foreach (&_bf_global_ctx->cgens, cgen_node)
            bf_cgen_unload(bf_list_node_get_data(cgen_node));
    }

    _bf_ctx_free(&_bf_global_ctx);
}

static void _bf_ctx_flush(struct bf_ctx *ctx)
{
    assert(ctx);

    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        bf_cgen_unload(cgen);
        bf_list_delete(&ctx->cgens, cgen_node);
    }
}

void bf_ctx_flush(void)
{
    _bf_ctx_flush(_bf_global_ctx);
}

void bf_ctx_dump(prefix_t *prefix)
{
    _bf_ctx_dump(_bf_global_ctx, prefix);
}

struct bf_cgen *bf_ctx_get_cgen(const char *name)
{
    return _bf_ctx_get_cgen(_bf_global_ctx, name);
}

int bf_ctx_get_cgens(bf_list *cgens)
{
    return _bf_ctx_get_cgens(_bf_global_ctx, cgens);
}

int bf_ctx_set_cgen(struct bf_cgen *cgen)
{
    return _bf_ctx_set_cgen(_bf_global_ctx, cgen);
}

int bf_ctx_delete_cgen(struct bf_cgen *cgen, bool unload)
{
    return _bf_ctx_delete_cgen(_bf_global_ctx, cgen, unload);
}

struct bf_ns *bf_ctx_get_ns(void)
{
    return &_bf_global_ctx->ns;
}

int bf_ctx_token(void)
{
    return _bf_global_ctx->token_fd;
}

int bf_ctx_get_pindir_fd(void)
{
    _cleanup_close_ int bpffs_fd = -1;
    _cleanup_close_ int pindir_fd = -1;

    bpffs_fd = bf_opendir(bf_opts_bpffs_path());
    if (bpffs_fd < 0) {
        return bf_err_r(bpffs_fd, "failed to open bpffs at %s",
                        bf_opts_bpffs_path());
    }

    pindir_fd = bf_opendir_at(bpffs_fd, "bpfilter", true);
    if (pindir_fd < 0) {
        return bf_err_r(pindir_fd, "failed to open pin directory %s/bpfilter",
                        bf_opts_bpffs_path());
    }

    return TAKE_FD(pindir_fd);
}

int bf_ctx_rm_pindir(void)
{
    _cleanup_close_ int bpffs_fd = -1;
    int r;

    bpffs_fd = bf_opendir(bf_opts_bpffs_path());
    if (bpffs_fd < 0) {
        return bf_err_r(bpffs_fd, "failed to open bpffs at %s",
                        bf_opts_bpffs_path());
    }

    r = bf_rmdir_at(bpffs_fd, "bpfilter", false);
    if (r < 0 && r != -ENOTEMPTY && r != -ENOENT)
        return bf_err_r(r, "failed to remove bpfilter bpffs directory");

    return 0;
}

const struct bf_elfstub *bf_ctx_get_elfstub(enum bf_elfstub_id id)
{
    return _bf_global_ctx->stubs[id];
}
