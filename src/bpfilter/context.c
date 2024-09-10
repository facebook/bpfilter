/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "context.h"

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "core/dump.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/logger.h"
#include "core/marsh.h"

#define _cleanup_bf_context_ __attribute__((cleanup(_bf_context_free)))

/// Global daemon context. Hidden in this translation unit.
static struct bf_context *_bf_global_context = NULL;

static void _bf_context_free(struct bf_context **context);

/**
 * Create and initialize a new context.
 *
 * On failure, @p context is left unchanged.
 *
 * @param context New context to create. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_context_new(struct bf_context **context)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;

    bf_assert(context);

    _context = calloc(1, sizeof(struct bf_context));
    if (!_context)
        return bf_err_r(errno, "failed to allocate memory");

    *context = TAKE_PTR(_context);

    return 0;
}

/**
 * Allocate a new context and initialise it from serialised data.
 *
 * @param context On success, points to the newly allocated and initialised
 *        context. Can't be NULL.
 * @param marsh Serialised data to use to initialise the context.
 * @return 0 on success, or negative errno value on failure.
 */
static int _bf_context_new_from_marsh(struct bf_context **context,
                                      const struct bf_marsh *marsh)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;
    struct bf_marsh *ctx_elem = NULL;
    struct bf_marsh *cgen_elem = NULL;
    int r;

    bf_assert(context);
    bf_assert(marsh);

    // Allocate a new context
    _context = calloc(1, sizeof(*_context));
    if (!_context)
        return -ENOMEM;

    // Unmarsh bf_context.cgens
    ctx_elem = bf_marsh_next_child(marsh, ctx_elem);
    if (!ctx_elem)
        return bf_err_r(-EINVAL, "failed to find valid child");

    while ((cgen_elem = bf_marsh_next_child(ctx_elem, cgen_elem))) {
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
        enum bf_hook hook;
        enum bf_front front;

        r = bf_cgen_unmarsh(cgen_elem, &cgen);
        if (r)
            return bf_err_r(r, "failed to unmarsh codegen");

        hook = cgen->hook;
        front = cgen->front;

        if (_context->cgens[hook][front]) {
            return bf_err_r(
                -EEXIST,
                "restored codegen for %s::%s, but codegen already exists in context!",
                bf_hook_to_str(hook), bf_front_to_str(front));
        }

        _context->cgens[hook][front] = TAKE_PTR(cgen);
    }

    *context = TAKE_PTR(_context);

    return 0;
}

/**
 * Free a context.
 *
 * If @p context points to a NULL pointer, this function does nothing. Once
 * the function returns, @p context points to a NULL pointer.
 *
 * @param context Context to free. Can't be NULL.
 */
static void _bf_context_free(struct bf_context **context)
{
    bf_assert(context);

    if (!*context)
        return;

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        for (int j = 0; j < _BF_FRONT_MAX; ++j)
            bf_cgen_free(&(*context)->cgens[i][j]);
    }

    free(*context);
    *context = NULL;
}

/**
 * See @ref bf_context_dump for details.
 */
static void _bf_context_dump(const struct bf_context *context, prefix_t *prefix)
{
    DUMP(prefix, "struct bf_context at %p", context);

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

            if (context->cgens[i][j]) {
                DUMP(prefix, "[%s]: struct bf_cgen *", bf_front_to_str(j));
                bf_dump_prefix_push(prefix);
                bf_cgen_dump(context->cgens[i][j], bf_dump_prefix_last(prefix));
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
 * @param context Context to marsh.
 * @param marsh Marsh'd context.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_context_marsh(const struct bf_context *context,
                             struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(context);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return bf_err_r(r, "failed to create marsh for context");

    {
        // Serialize bf_context.cgens content
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return bf_err_r(r, "failed to create marsh for codegens");

        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            for (int j = 0; j < _BF_FRONT_MAX; ++j) {
                _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
                struct bf_cgen *cgen = context->cgens[i][j];

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
 * See @ref bf_context_get_cgen for details.
 */
static struct bf_cgen *_bf_context_get_cgen(const struct bf_context *context,
                                            enum bf_hook hook,
                                            enum bf_front front)
{
    bf_assert(context);

    return context->cgens[hook][front];
}

/**
 * See @ref bf_context_take_cgen for details.
 */
static struct bf_cgen *_bf_context_take_cgen(struct bf_context *context,
                                             enum bf_hook hook,
                                             enum bf_front front)
{
    bf_assert(context);

    return TAKE_PTR(context->cgens[hook][front]);
}

/**
 * See @ref bf_context_delete_cgen for details.
 */
static void _bf_context_delete_cgen(struct bf_context *context,
                                    enum bf_hook hook, enum bf_front front)
{
    bf_assert(context);

    bf_cgen_free(&context->cgens[hook][front]);
}

/**
 * See @ref bf_context_set_cgen for details.
 */
static int _bf_context_set_cgen(struct bf_context *context, enum bf_hook hook,
                                enum bf_front front, struct bf_cgen *cgen)
{
    bf_assert(context);
    bf_assert(cgen && cgen->hook == hook && cgen->front == front);

    if (context->cgens[hook][front])
        return bf_err_r(-EEXIST, "codegen already exists in context");

    context->cgens[hook][front] = cgen;

    return 0;
}

/**
 * See @ref bf_context_replace_cgen for details.
 */
static void _bf_context_replace_cgen(struct bf_context *context,
                                     enum bf_hook hook, enum bf_front front,
                                     struct bf_cgen *cgen)
{
    bf_assert(context);

    bf_cgen_free(&context->cgens[hook][front]);
    context->cgens[hook][front] = cgen;
}

int bf_context_setup(void)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;
    int r;

    bf_assert(!_context);

    r = _bf_context_new(&_context);
    if (r)
        return bf_err_r(r, "failed to create new context");

    _bf_global_context = TAKE_PTR(_context);

    return 0;
}

void bf_context_teardown(bool clear)
{
    if (clear) {
        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            for (int j = 0; j < _BF_FRONT_MAX; ++j) {
                if (!_bf_global_context->cgens[i][j])
                    continue;

                bf_cgen_unload(_bf_global_context->cgens[i][j]);
            }
        }
    }

    _bf_context_free(&_bf_global_context);
}

int bf_context_save(struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(marsh);

    r = _bf_context_marsh(_bf_global_context, &_marsh);
    if (r)
        return bf_err_r(r, "failed to serialize context");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_context_load(const struct bf_marsh *marsh)
{
    _cleanup_bf_context_ struct bf_context *context = NULL;
    int r;

    bf_assert(marsh);

    r = _bf_context_new_from_marsh(&context, marsh);
    if (r)
        return bf_err_r(r, "failed to deserialize context");

    _bf_global_context = TAKE_PTR(context);

    return 0;
}

void bf_context_dump(prefix_t *prefix)
{
    _bf_context_dump(_bf_global_context, prefix);
}

struct bf_cgen *bf_context_get_cgen(enum bf_hook hook, enum bf_front front)
{
    return _bf_context_get_cgen(_bf_global_context, hook, front);
}

struct bf_cgen *bf_context_take_cgen(enum bf_hook hook, enum bf_front front)
{
    return _bf_context_take_cgen(_bf_global_context, hook, front);
}

void bf_context_delete_cgen(enum bf_hook hook, enum bf_front front)
{
    _bf_context_delete_cgen(_bf_global_context, hook, front);
}

int bf_context_set_cgen(enum bf_hook hook, enum bf_front front,
                        struct bf_cgen *cgen)
{
    return _bf_context_set_cgen(_bf_global_context, hook, front, cgen);
}

void bf_context_replace_cgen(enum bf_hook hook, enum bf_front front,
                             struct bf_cgen *cgen)
{
    _bf_context_replace_cgen(_bf_global_context, hook, front, cgen);
}
