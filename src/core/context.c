/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "context.h"

#include <errno.h>
#include <stdlib.h>

#include "core/logger.h"
#include "core/marsh.h"
#include "generator/codegen.h"
#include "shared/helper.h"

#define _cleanup_bf_context_ __attribute__((cleanup(_bf_context_free)))

/// Global daemon context. Hidden in this translation unit.
static struct bf_context *_global_context = NULL;

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
        return bf_err_code(errno, "failed to allocate memory");

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
    struct bf_marsh *child = NULL;
    struct bf_marsh *subchild = NULL;
    int r;

    bf_assert(context);
    bf_assert(marsh);

    // Allocate a new codegen
    _context = calloc(1, sizeof(*_context));
    if (!_context)
        return -ENOMEM;

    // Unmarsh bf_context.codegens
    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return bf_err_code(-EINVAL, "failed to find valid child");

    while ((subchild = bf_marsh_next_child(child, subchild))) {
        _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;
        enum bf_hook hook;
        enum bf_front front;

        r = bf_codegen_unmarsh(subchild, &codegen);
        if (r)
            return bf_err_code(r, "failed to unmarsh codegen");

        hook = codegen->hook;
        front = codegen->front;

        if (_context->codegens[hook][front]) {
            return bf_err_code(
                -EEXIST,
                "restored codegen for %s::%s, but codegen already exists in context!",
                bf_hook_to_str(hook), bf_front_to_str(front));
        }

        _context->codegens[hook][front] = TAKE_PTR(codegen);
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
            bf_codegen_free(&(*context)->codegens[i][j]);
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

    DUMP(bf_dump_prefix_last(prefix), "codegens: bf_codegen[%d][%d]",
         _BF_HOOK_MAX, _BF_FRONT_MAX);
    bf_dump_prefix_push(prefix);

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        if (i == _BF_HOOK_MAX - 1)
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "[%s]", bf_hook_to_str(i));
        bf_dump_prefix_push(prefix);

        for (int j = 0; j < _BF_FRONT_MAX; ++j) {
            if (j == _BF_FRONT_MAX - 1)
                bf_dump_prefix_last(prefix);

            if (context->codegens[i][j]) {
                DUMP(prefix, "[%s]: struct bf_codegen *", bf_front_to_str(j));
                bf_dump_prefix_push(prefix);
                bf_codegen_dump(context->codegens[i][j],
                                bf_dump_prefix_last(prefix));
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
        return bf_err_code(r, "failed to create marsh for context");

    {
        // Serialize bf_context.codegens content
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return bf_err_code(r, "failed to create marsh for codegens");

        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            for (int j = 0; j < _BF_FRONT_MAX; ++j) {
                _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
                struct bf_codegen *codegen = context->codegens[i][j];

                if (!codegen)
                    continue;

                r = bf_codegen_marsh(codegen, &subchild);
                if (r)
                    return bf_err_code(r, "failed to marsh codegen");

                r = bf_marsh_add_child_obj(&child, subchild);
                if (r)
                    return bf_err_code(r, "failed to append codegen marsh");

                /* Don't TAKE_PTR(subchild), it's copied to child, so now
                 * it can be destroyed. */
            }
        }

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return bf_err_code(r, "failed to append object to marsh");

        /* Don't TAKE_PTR(child), it's copied to child, so now
         * it can be destroyed. */
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

/**
 * See @ref bf_context_get_codegen for details.
 */
static struct bf_codegen *
_bf_context_get_codegen(const struct bf_context *context, enum bf_hook hook,
                        enum bf_front front)
{
    bf_assert(context);

    return context->codegens[hook][front];
}

/**
 * See @ref bf_context_take_codegen for details.
 */
static struct bf_codegen *_bf_context_take_codegen(struct bf_context *context,
                                                   enum bf_hook hook,
                                                   enum bf_front front)
{
    bf_assert(context);

    return TAKE_PTR(context->codegens[hook][front]);
}

/**
 * See @ref bf_context_delete_codegen for details.
 */
static void _bf_context_delete_codegen(struct bf_context *context,
                                       enum bf_hook hook, enum bf_front front)
{
    bf_assert(context);

    bf_codegen_free(&context->codegens[hook][front]);
}

/**
 * See @ref bf_context_set_codegen for details.
 */
static int _bf_context_set_codegen(struct bf_context *context,
                                   enum bf_hook hook, enum bf_front front,
                                   struct bf_codegen *codegen)
{
    bf_assert(context);
    bf_assert(codegen && codegen->hook == hook && codegen->front == front);

    if (context->codegens[hook][front])
        return bf_err_code(-EEXIST, "codegen already exists in context");

    context->codegens[hook][front] = codegen;

    return 0;
}

/**
 * See @ref bf_context_replace_codegen for details.
 */
static void _bf_context_replace_codegen(struct bf_context *context,
                                        enum bf_hook hook, enum bf_front front,
                                        struct bf_codegen *codegen)
{
    bf_assert(context);

    bf_codegen_free(&context->codegens[hook][front]);
    context->codegens[hook][front] = codegen;
}

int bf_context_setup(void)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;
    int r;

    bf_assert(!_context);

    r = _bf_context_new(&_context);
    if (r)
        return bf_err_code(r, "failed to create new context");

    _global_context = TAKE_PTR(_context);

    return 0;
}

void bf_context_teardown(bool clear)
{
    if (clear) {
        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            for (int j = 0; j < _BF_FRONT_MAX; ++j) {
                if (!_global_context->codegens[i][j])
                    continue;

                bf_codegen_unload(_global_context->codegens[i][j]);
            }
        }
    }

    _bf_context_free(&_global_context);
}

int bf_context_save(struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(marsh);

    r = _bf_context_marsh(_global_context, &_marsh);
    if (r)
        return bf_err_code(r, "failed to serialize context");

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
        return bf_err_code(r, "failed to deserialize context");

    _global_context = TAKE_PTR(context);

    return 0;
}

void bf_context_dump(prefix_t *prefix)
{
    _bf_context_dump(_global_context, prefix);
}

struct bf_codegen *bf_context_get_codegen(enum bf_hook hook,
                                          enum bf_front front)
{
    return _bf_context_get_codegen(_global_context, hook, front);
}

struct bf_codegen *bf_context_take_codegen(enum bf_hook hook,
                                           enum bf_front front)
{
    return _bf_context_take_codegen(_global_context, hook, front);
}

void bf_context_delete_codegen(enum bf_hook hook, enum bf_front front)
{
    _bf_context_delete_codegen(_global_context, hook, front);
}

int bf_context_set_codegen(enum bf_hook hook, enum bf_front front,
                           struct bf_codegen *codegen)
{
    return _bf_context_set_codegen(_global_context, hook, front, codegen);
}

void bf_context_replace_codegen(enum bf_hook hook, enum bf_front front,
                                struct bf_codegen *codegen)
{
    _bf_context_replace_codegen(_global_context, hook, front, codegen);
}
