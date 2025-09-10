/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "ctx.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/elfstub.h"
#include "bpfilter/opts.h"
#include "core/bpf.h"
#include "core/btf.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/io.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/ns.h"
#include "core/pack.h"

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

    bf_assert(ctx);

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
 * @brief Allocate and initialize a new context from serialized data.
 *
 * @param ctx Context object to allocate and initialize from the serialized
 *        data. The caller will own the object. On failure, `*ctx` is
 *        unchanged. Can't be NULL.
 * @param node Node containing the serialized matcher.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_ctx_new_from_pack(struct bf_ctx **ctx, bf_rpack_node_t node)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    bf_rpack_node_t child, array_node;
    int r;

    bf_assert(ctx);

    r = _bf_ctx_new(&_ctx);
    if (r < 0)
        return r;

    r = bf_rpack_kv_array(node, "cgens", &child);
    if (r)
        return r;
    bf_rpack_array_foreach (child, array_node) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;

        r = bf_list_emplace(&_ctx->cgens, bf_cgen_new_from_pack, cgen,
                            array_node);
        if (r)
            return r;
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
    bf_assert(ctx);

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
 * @brief Serialize a context.
 *
 * The context is serialized as:
 * @code
 * {
 *   "cgens": [
 *     { bf_codegen },
 *     // ...
 *   ]
 * }
 * @endcode
 *
 * @param ctx Context to serialize. Can't be NULL.
 * @param pack `bf_wpack_t` object to serialize the context into. Can't be NULL.
 * @return 0 on success, or a negative error value on failure.
 */
static int _bf_ctx_pack(const struct bf_ctx *ctx, bf_wpack_t *pack)
{
    bf_assert(ctx);
    bf_assert(pack);

    bf_wpack_kv_list(pack, "cgens", &ctx->cgens);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

/**
 * See @ref bf_ctx_get_cgen for details.
 */
static struct bf_cgen *_bf_ctx_get_cgen(const struct bf_ctx *ctx,
                                        const char *name)
{
    bf_assert(ctx && name);

    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (bf_streq(cgen->chain->name, name))
            return cgen;
    }

    return NULL;
}

/**
 * See @ref bf_ctx_get_cgens_for_front for details.
 */
static int _bf_ctx_get_cgens_for_front(const struct bf_ctx *ctx, bf_list *cgens,
                                       enum bf_front front)
{
    _clean_bf_list_ bf_list _cgens =
        bf_list_default(cgens->ops.free, cgens->ops.pack);
    int r;

    bf_assert(ctx && cgens);

    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (cgen->front != front)
            continue;

        r = bf_list_add_tail(&_cgens, cgen);
        if (r)
            return bf_err_r(r, "failed to insert codegen into list");
    }

    *cgens = bf_list_move(_cgens);

    return 0;
}

/**
 * See @ref bf_ctx_set_cgen for details.
 */
static int _bf_ctx_set_cgen(struct bf_ctx *ctx, struct bf_cgen *cgen)
{
    bf_assert(ctx && cgen);

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

int bf_ctx_setup(void)
{
    _free_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    bf_assert(!_ctx);

    r = _bf_ctx_new(&_ctx);
    if (r)
        return bf_err_r(r, "failed to create new context");

    _bf_global_ctx = TAKE_PTR(_ctx);

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

int bf_ctx_save(bf_wpack_t *pack)
{
    int r;

    bf_assert(pack);

    r = _bf_ctx_pack(_bf_global_ctx, pack);
    if (r)
        return bf_err_r(r, "failed to serialize context");

    return 0;
}

int bf_ctx_load(bf_rpack_node_t node)
{
    _free_bf_ctx_ struct bf_ctx *ctx = NULL;
    int r;

    r = _bf_ctx_new_from_pack(&ctx, node);
    if (r)
        return bf_err_r(r, "failed to deserialize context");

    _bf_global_ctx = TAKE_PTR(ctx);

    return 0;
}

static void _bf_ctx_flush(struct bf_ctx *ctx, enum bf_front front)
{
    bf_assert(ctx);

    bf_list_foreach (&ctx->cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (cgen->front != front)
            continue;

        bf_cgen_unload(cgen);
        bf_list_delete(&ctx->cgens, cgen_node);
    }
}

void bf_ctx_flush(enum bf_front front)
{
    _bf_ctx_flush(_bf_global_ctx, front);
}

bool bf_ctx_is_empty(void)
{
    return bf_list_is_empty(&_bf_global_ctx->cgens);
}

void bf_ctx_dump(prefix_t *prefix)
{
    _bf_ctx_dump(_bf_global_ctx, prefix);
}

struct bf_cgen *bf_ctx_get_cgen(const char *name)
{
    return _bf_ctx_get_cgen(_bf_global_ctx, name);
}

int bf_ctx_get_cgens_for_front(bf_list *cgens, enum bf_front front)
{
    return _bf_ctx_get_cgens_for_front(_bf_global_ctx, cgens, front);
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
