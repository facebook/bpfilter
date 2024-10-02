/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "ctx.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/marsh.h"

#define _cleanup_bf_ctx_ __attribute__((cleanup(_bf_ctx_free)))

/// Global daemon context. Hidden in this translation unit.
static struct bf_ctx *_bf_global_ctx = NULL;

static void _bf_ctx_free(struct bf_ctx **ctx);

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
    bf_assert(ctx);

    *ctx = calloc(1, sizeof(struct bf_ctx));
    if (!*ctx)
        return -ENOMEM;

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
    struct bf_marsh *ctx_elem = NULL;
    struct bf_marsh *cgen_elem = NULL;
    int r;

    bf_assert(ctx);
    bf_assert(marsh);

    // Allocate a new ctx
    _ctx = calloc(1, sizeof(*_ctx));
    if (!_ctx)
        return -ENOMEM;

    // Unmarsh bf_ctx.cgens
    ctx_elem = bf_marsh_next_child(marsh, ctx_elem);
    if (!ctx_elem)
        return bf_err_r(-EINVAL, "failed to find valid child");

    while ((cgen_elem = bf_marsh_next_child(ctx_elem, cgen_elem))) {
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
        enum bf_hook hook;
        enum bf_front front;

        r = bf_cgen_new_from_marsh(&cgen, cgen_elem);
        if (r)
            return bf_err_r(r, "failed to unmarsh codegen");

        hook = cgen->chain->hook;
        front = cgen->front;

        if (_ctx->cgens[hook][front]) {
            return bf_err_r(
                -EEXIST,
                "restored codegen for %s::%s, but codegen already exists in context!",
                bf_hook_to_str(hook), bf_front_to_str(front));
        }

        _ctx->cgens[hook][front] = TAKE_PTR(cgen);
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

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        for (int j = 0; j < _BF_FRONT_MAX; ++j)
            bf_cgen_free(&(*ctx)->cgens[i][j]);
    }

    freep((void *)ctx);
}

/**
 * See @ref bf_ctx_dump for details.
 */
static void _bf_ctx_dump(const struct bf_ctx *ctx, prefix_t *prefix)
{
    DUMP(prefix, "struct bf_ctx at %p", ctx);

    bf_dump_prefix_push(prefix);

    DUMP(bf_dump_prefix_last(prefix), "cgens: bf_cgen[%d][%d]", _BF_HOOK_MAX,
         _BF_FRONT_MAX);
    bf_dump_prefix_push(prefix);

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        if (i == _BF_HOOK_MAX - 1)
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "[%s]", bf_hook_to_str(i));
        bf_dump_prefix_push(prefix);

        for (int j = 0; j < _BF_FRONT_MAX; ++j) {
            if (j == _BF_FRONT_MAX - 1)
                bf_dump_prefix_last(prefix);

            if (ctx->cgens[i][j]) {
                DUMP(prefix, "[%s]: struct bf_cgen *", bf_front_to_str(j));
                bf_dump_prefix_push(prefix);
                bf_cgen_dump(ctx->cgens[i][j], bf_dump_prefix_last(prefix));
                bf_dump_prefix_pop(prefix);
            } else {
                DUMP(prefix, "[%s]: <null>", bf_front_to_str(j));
            }
        }

        bf_dump_prefix_pop(prefix);
    }
}

/**
 * Marsh a context.
 *
 * If the function succeeds, @p marsh will contain the marshalled context.
 *
 * @param ctx Context to marsh.
 * @param marsh Marsh'd context.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_ctx_marsh(const struct bf_ctx *ctx, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(ctx);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return bf_err_r(r, "failed to create marsh for context");

    {
        // Serialize bf_ctx.cgens content
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return bf_err_r(r, "failed to create marsh for codegens");

        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            for (int j = 0; j < _BF_FRONT_MAX; ++j) {
                _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
                struct bf_cgen *cgen = ctx->cgens[i][j];

                if (!cgen)
                    continue;

                r = bf_cgen_marsh(cgen, &subchild);
                if (r)
                    return bf_err_r(r, "failed to marsh codegen");

                r = bf_marsh_add_child_obj(&child, subchild);
                if (r)
                    return bf_err_r(r, "failed to append codegen marsh");

                /* Don't TAKE_PTR(subchild), it's copied to child, so now
                 * it can be destroyed. */
            }
        }

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return bf_err_r(r, "failed to append object to marsh");

        /* Don't TAKE_PTR(child), it's copied to child, so now
         * it can be destroyed. */
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

/**
 * See @ref bf_ctx_get_cgen for details.
 */
static struct bf_cgen *_bf_ctx_get_cgen(const struct bf_ctx *ctx,
                                        enum bf_hook hook, enum bf_front front)
{
    bf_assert(ctx);

    return ctx->cgens[hook][front];
}

/**
 * See @ref bf_ctx_set_cgen for details.
 */
static int _bf_ctx_set_cgen(struct bf_ctx *ctx, enum bf_hook hook,
                            enum bf_front front, struct bf_cgen *cgen)
{
    bf_assert(ctx);
    bf_assert(cgen && cgen->chain->hook == hook && cgen->front == front);

    if (ctx->cgens[hook][front])
        return bf_err_r(-EEXIST, "codegen already exists in context");

    ctx->cgens[hook][front] = cgen;

    return 0;
}

/**
 * See @ref bf_ctx_replace_cgen for details.
 */
static void _bf_ctx_replace_cgen(struct bf_ctx *ctx, enum bf_hook hook,
                                 enum bf_front front, struct bf_cgen *cgen)
{
    bf_assert(ctx);

    bf_cgen_free(&ctx->cgens[hook][front]);
    ctx->cgens[hook][front] = cgen;
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
        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            for (int j = 0; j < _BF_FRONT_MAX; ++j) {
                if (!_bf_global_ctx->cgens[i][j])
                    continue;

                bf_cgen_unload(_bf_global_ctx->cgens[i][j]);
            }
        }
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

void bf_ctx_dump(prefix_t *prefix)
{
    _bf_ctx_dump(_bf_global_ctx, prefix);
}

struct bf_cgen *bf_ctx_get_cgen(enum bf_hook hook, enum bf_front front)
{
    return _bf_ctx_get_cgen(_bf_global_ctx, hook, front);
}

int bf_ctx_set_cgen(enum bf_hook hook, enum bf_front front,
                    struct bf_cgen *cgen)
{
    return _bf_ctx_set_cgen(_bf_global_ctx, hook, front, cgen);
}

void bf_ctx_replace_cgen(enum bf_hook hook, enum bf_front front,
                         struct bf_cgen *cgen)
{
    _bf_ctx_replace_cgen(_bf_global_ctx, hook, front, cgen);
}
