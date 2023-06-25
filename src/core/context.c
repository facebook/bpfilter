/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "context.h"

#include <assert.h>
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
static const struct bf_list_node *
_bf_context_get_next_codegen_node_by_hook(const struct bf_context *context,
                                          const struct bf_list_node *node,
                                          enum bf_hook hook);

/**
 * @brief Create and initialize a new context.
 *
 * On failure, @p context is left unchanged.
 *
 * @param context New context to create. Can't be NULL.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_context_new(struct bf_context **context)
{
    static const bf_list_ops ops = {
        .free = (bf_list_ops_free)bf_codegen_free,
    };

    _cleanup_bf_context_ struct bf_context *_context = NULL;

    assert(context);

    _context = calloc(1, sizeof(struct bf_context));
    if (!_context)
        return bf_err_code(errno, "failed to allocate memory");

    for (int i = 0; i < _BF_HOOK_MAX; ++i)
        bf_list_init(&_context->hooks[i], &ops);

    *context = TAKE_PTR(_context);

    return 0;
}

/**
 * @brief Free a context.
 *
 * If @p context points to a NULL pointer, this function does nothing. Once
 * the function returns, @p context points to a NULL pointer.
 *
 * @param context Context to free. Can't be NULL.
 */
static void _bf_context_free(struct bf_context **context)
{
    assert(context);

    if (!*context)
        return;

    for (int i = 0; i < _BF_HOOK_MAX; ++i)
        bf_list_clean(&(*context)->hooks[i]);

    free(*context);
    *context = NULL;
}

/**
 * See @ref bf_context_dump for details.
 */
static void _bf_context_dump(const struct bf_context *context, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;

    DUMP(prefix, "struct bf_context at %p", context);

    bf_dump_prefix_push(prefix);

    DUMP(bf_dump_prefix_last(prefix), "hooks:");
    bf_dump_prefix_push(prefix);

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        if (i == BF_HOOK_TC_EGRESS)
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "%s", bf_hook_to_str(i));
        bf_dump_prefix_push(prefix);

        bf_list_foreach (&context->hooks[i], codegen_node) {
            if (bf_list_is_tail(&context->hooks[i], codegen_node))
                bf_dump_prefix_last(prefix);

            bf_codegen_dump(bf_list_node_get_data(codegen_node), prefix);
        }

        bf_dump_prefix_pop(prefix);
    }
}

/**
 * @brief Marsh a context.
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

    assert(context);
    assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return bf_err_code(r, "failed to create marsh for context");

    {
        // Serialize bf_context.hooks content (struct bf_codegen)

        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return bf_err_code(r, "failed to create marsh for codegens");

        for (int i = 0; i < _BF_HOOK_MAX; ++i) {
            bf_list_foreach (&context->hooks[i], codegen_node) {
                _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
                struct bf_codegen *codegen =
                    bf_list_node_get_data(codegen_node);

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
 * @brief Unmarsh a context.
 *
 * @p marsh is expected to be valid, that is @p marsh.data_len argument is
 * within bound regarding actual size of @p marsh.
 *
 * @param marsh Marsh'd context to restore.
 * @param context Restored context.
 * @return 0 on success, negative errno value on failure.
 */
static int _bf_context_unmarsh(const struct bf_marsh *marsh,
                               struct bf_context **context)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;
    struct bf_marsh *child;
    int r;

    assert(marsh);
    assert(context);

    child = bf_marsh_next_child(marsh, NULL);
    if (!child)
        return bf_err_code(-EINVAL, "failed to find valid child");

    r = _bf_context_new(&_context);
    if (r)
        return bf_err_code(r, "failed to create new context");

    {
        // Unmarsh codegens
        struct bf_marsh *subchild = NULL;

        while ((subchild = bf_marsh_next_child(child, subchild))) {
            _cleanup_bf_codegen_ struct bf_codegen *codegen = NULL;

            r = bf_codegen_unmarsh(subchild, &codegen);
            if (r)
                return bf_err_code(r, "failed to unmarsh codegen");

            r = bf_list_add_head(&_context->hooks[codegen->hook], codegen);
            if (r)
                return bf_err_code(r, "failed to add codegen to context");

            TAKE_PTR(codegen);
        }
    }

    *context = TAKE_PTR(_context);

    return 0;
}

/**
 * See @ref bf_context_get_codegen for details.
 */
static struct bf_codegen *
_bf_context_get_codegen(const struct bf_context *context, enum bf_hook hook,
                        enum bf_front front)
{
    assert(context);

    bf_context_foreach_codegen_by_hook(codegen, hook)
    {
        if (codegen->front == front)
            return codegen;
    }

    return NULL;
}

/**
 * See @ref bf_context_take_codegen for details.
 */
static struct bf_codegen *_bf_context_take_codegen(struct bf_context *context,
                                                   enum bf_hook hook,
                                                   enum bf_front front)
{
    assert(context);

    /* Use bf_list_foreach() instead of bf_context-specific functions so the
     * node can be deleted while iterating. the node can be */
    bf_list_foreach (&context->hooks[hook], codegen_node) {
        struct bf_codegen *codegen = bf_list_node_get_data(codegen_node);
        if (codegen->front != front)
            continue;

        codegen = bf_list_node_take_data(codegen_node);
        bf_list_delete(&context->hooks[hook], codegen_node);
        return codegen;
    }

    return NULL;
}

/**
 * See @ref bf_context_delete_codegen for details.
 */
static void _bf_context_delete_codegen(struct bf_context *context,
                                       enum bf_hook hook, enum bf_front front)
{
    struct bf_codegen *codegen = NULL;

    assert(context);

    codegen = _bf_context_take_codegen(context, hook, front);
    bf_codegen_free(&codegen);
}

/**
 * See @ref bf_context_set_codegen for details.
 */
static int _bf_context_set_codegen(struct bf_context *context,
                                   enum bf_hook hook, enum bf_front front,
                                   struct bf_codegen *codegen)
{
    assert(context);
    assert(codegen && codegen->hook == hook && codegen->front == front);

    if (_bf_context_get_codegen(context, hook, front))
        return bf_err_code(-EEXIST, "codegen already exists in context");

    return bf_list_add_tail(&context->hooks[hook], codegen);
}

/**
 * See @ref bf_context_update_codegen for details.
 */
static int _bf_context_update_codegen(struct bf_context *context,
                                      enum bf_hook hook, enum bf_front front,
                                      struct bf_codegen *codegen)
{
    assert(context);

    _bf_context_delete_codegen(context, hook, front);

    return bf_list_add_tail(&context->hooks[hook], codegen);
}

/**
 * @brief Get the next codegen list node.
 *
 * For a given @p node, this function returns the next codegen list node. It
 * will jump accross hooks if no more codegen are available for the current
 * hook.
 *
 * if @p node is NULL, the first codegen node is returned.
 *
 * @param context Context to get the codegen from.
 * @param node Node to get the next codegen from, or NULL.
 * @return The next codegen, or NULL if there is no more.
 */
static const struct bf_list_node *
_bf_context_get_next_codegen_node(const struct bf_context *context,
                                  const struct bf_list_node *node)
{
    enum bf_hook i =
        node ? ((struct bf_codegen *)bf_list_node_get_data(node))->hook : 0;

    assert(context);

    for (; i < _BF_HOOK_MAX; ++i) {
        node = _bf_context_get_next_codegen_node_by_hook(context, node, i);
        if (node)
            return node;
    }

    return NULL;
}

/**
 * @brief Get the next codegen list node for a given hook.
 *
 * @p node is expected to be a valid codegen node for the given hook. If @p node
 * is NULL, the first codegen node for the given hook is returned.
 *
 * @warning This function is not supposed to be called directly. Use the
 *  @ref bf_context_foreach_codegen_by_hook macro instead to iterate over
 *  codegen for a given hook.
 *
 * @param context Context to get the codegen from.
 * @param node Node to get the next codegen from, or NULL.
 * @param hook Hook to get the codegen from. Must be a valid hook.
 * @return The next codegen for the given hook, or NULL if there is no more.
 */
static const struct bf_list_node *
_bf_context_get_next_codegen_node_by_hook(const struct bf_context *context,
                                          const struct bf_list_node *node,
                                          enum bf_hook hook)
{
    assert(context);

    if (!node)
        return bf_list_get_head(&context->hooks[hook]);

    return bf_list_node_next(node);
}

/**
 * @brief Get the next codegen list node for a given front-end.
 *
 * @p node is expected to be a valid codegen node for the given front-end. If
 * @p node is NULL, the first codegen node for the given front-end is returned.
 *
 * @warning This function is not supposed to be called directly. Use the
 * @ref bf_context_foreach_codegen_by_fe macro instead to iterate over
 * codegen for a given front-end.
 *
 * @param context Context to get the codegen from.
 * @param node Node to get the next codegen from, or NULL.
 * @param fe Front-end to get the codegen from. Must be a valid front-end.
 * @return The next codegen for the given front-end, or NULL if there is no
 * more.
 */
static const struct bf_list_node *
_bf_context_get_next_codegen_node_by_fe(const struct bf_context *context,
                                        const struct bf_list_node *node,
                                        enum bf_front front)
{
    assert(context);

    while ((node = _bf_context_get_next_codegen_node(context, node))) {
        if (((struct bf_codegen *)bf_list_node_get_data(node))->front == front)
            return node;
    }

    return NULL;
}

int bf_context_setup(void)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;
    int r;

    assert(!_context);

    r = _bf_context_new(&_context);
    if (r)
        return bf_err_code(r, "failed to create new context");

    _global_context = TAKE_PTR(_context);

    return 0;
}

void bf_context_teardown(void)
{
    _bf_context_free(&_global_context);
}

int bf_context_save(struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    assert(marsh);

    r = _bf_context_marsh(_global_context, &_marsh);
    if (r)
        return bf_err_code(r, "failed to serialize context");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_context_load(const struct bf_marsh *marsh)
{
    _cleanup_bf_context_ struct bf_context *_context = NULL;
    int r;

    assert(marsh);

    r = _bf_context_unmarsh(marsh, &_context);
    if (r)
        return bf_err_code(r, "failed to deserialize context");

    _global_context = TAKE_PTR(_context);

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

int bf_context_update_codegen(enum bf_hook hook, enum bf_front front,
                              struct bf_codegen *codegen)
{
    return _bf_context_update_codegen(_global_context, hook, front, codegen);
}

struct bf_codegen *bf_context_get_next_codegen(const void **iter)
{
    assert(iter);

    *iter = _bf_context_get_next_codegen_node(_global_context, *iter);

    return (*iter) ? bf_list_node_get_data(*iter) : NULL;
}

struct bf_codegen *bf_context_get_next_codegen_by_hook(const void **iter,
                                                       enum bf_hook hook)
{
    assert(iter);

    *iter =
        _bf_context_get_next_codegen_node_by_hook(_global_context, *iter, hook);

    return (*iter) ? bf_list_node_get_data(*iter) : NULL;
}

struct bf_codegen *bf_context_get_next_codegen_by_fe(const void **iter,
                                                     enum bf_front front)
{
    assert(iter);

    *iter =
        _bf_context_get_next_codegen_node_by_fe(_global_context, *iter, front);

    return (*iter) ? bf_list_node_get_data(*iter) : NULL;
}
