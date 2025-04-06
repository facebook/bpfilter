/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "ctx.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include "bpfilter/cgen/cgen.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/ns.h"

#define _cleanup_bf_ctx_ __attribute__((cleanup(_bf_ctx_free)))

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

    bf_list cgens;
};

static void _bf_ctx_free(struct bf_ctx **ctx);

/// Global daemon context. Hidden in this translation unit.
static struct bf_ctx *_bf_global_ctx = NULL;

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
    _cleanup_bf_ctx_ struct bf_ctx *_ctx = NULL;
    int r;

    bf_assert(ctx);

    _ctx = malloc(sizeof(*_ctx));
    if (!_ctx)
        return -ENOMEM;

    r = bf_ns_init(&_ctx->ns, getpid());
    if (r)
        return bf_err_r(r, "failed to initialise current bf_ns");

    _ctx->cgens = bf_list_default(bf_cgen_free, bf_cgen_marsh);

    *ctx = TAKE_PTR(_ctx);

    return 0;
}

/**
 * Allocate a new context and initialise it from serialised data.
 *
 * @param ctx On success, points to the newly allocated and initialised
 *        context. Can't be NULL.
 * @param marsh Serialised data to use to initialise the context.
 * @return 0 on success, or negative errno value on failure.
 */
static int _bf_ctx_new_from_marsh(struct bf_ctx **ctx,
                                  const struct bf_marsh *marsh)
{
    _cleanup_bf_ctx_ struct bf_ctx *_ctx = NULL;
    struct bf_marsh *child = NULL;
    struct bf_marsh *elem = NULL;
    int r;

    bf_assert(ctx && marsh);

    r = _bf_ctx_new(&_ctx);
    if (r < 0)
        return r;

    // Unmarsh bf_ctx.cgens
    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    while ((elem = bf_marsh_next_child(child, elem))) {
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;

        r = bf_cgen_new_from_marsh(&cgen, elem);
        if (r < 0)
            return r;

        r = bf_list_add_tail(&_ctx->cgens, cgen);
        if (r < 0)
            return r;

        TAKE_PTR(cgen);
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
    bf_list_clean(&(*ctx)->cgens);
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
 * Marsh a context.
 *
 * If the function succeeds, @p marsh will contain the marshalled context.
 *
 * @ref bf_ctx only contain the codegens, so the serialized data can be
 * flattened to:
 *   - ctx marsh
 *     - list marsh
 *       - cgen marsh
 *       - ...
 *     - list marsh
 *     - ...
 *
 * @param ctx Context to marsh.
 * @param marsh Marsh'd context.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_ctx_marsh(const struct bf_ctx *ctx, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(ctx && marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return bf_err_r(r, "failed to create marsh for context");

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_list_marsh(&ctx->cgens, &child);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return bf_err_r(r, "failed to append codegen marsh");
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
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
        bf_list_default(cgens->ops.free, cgens->ops.marsh);
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
    _cleanup_bf_ctx_ struct bf_ctx *_ctx = NULL;
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

int bf_ctx_save(struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(marsh);

    r = _bf_ctx_marsh(_bf_global_ctx, &_marsh);
    if (r)
        return bf_err_r(r, "failed to serialize context");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_ctx_load(const struct bf_marsh *marsh)
{
    _cleanup_bf_ctx_ struct bf_ctx *ctx = NULL;
    int r;

    bf_assert(marsh);

    r = _bf_ctx_new_from_marsh(&ctx, marsh);
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
