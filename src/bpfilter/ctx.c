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
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"

#define _cleanup_bf_ctx_ __attribute__((cleanup(_bf_ctx_free)))

/**
 * @struct bf_ctx
 *
 * bpfilter working context. Only one context is used during the daemon's
 * lifetime.
 */
struct bf_ctx
{
    /// Codegens defined in bpfilter. Defined as an array of lists as some
    /// hooks can have multiple codegens (e.g. XDP).
    bf_list cgens[_BF_HOOK_MAX];
};

static void _bf_ctx_free(struct bf_ctx **ctx);

/// Global daemon context. Hidden in this translation unit.
static struct bf_ctx *_bf_global_ctx = NULL;

/**
 * Get the requested BF_HOOK_XDP codegen from the list.
 *
 * Use @c opts->ifindex to find the expected codegen and return it.
 *
 * @param list List containing all the BF_HOOK_XDP codegens. Can't be NULL.
 * @param opts Hook options, @c opts->ifindex is used to find the correct
 *        codegen. Can't be NULL.
 * @return The request codegen, or NULL if not found.
 */
static struct bf_cgen *_bf_ctx_get_xdp_cgen(const bf_list *list,
                                            const struct bf_hook_opts *opts)
{
    bf_list_foreach (list, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (cgen->chain->hook_opts.ifindex == opts->ifindex)
            return cgen;
    }

    return NULL;
}

/**
 * Get the requested BF_HOOK_NF_* codegen from the list.
 *
 * There can be only one codegen defined for each BF_HOOK_NF_* hook, so we
 * return the first of the list, if defined.
 *
 * @param list List containing all the BF_HOOK_NF_* codegens. Can't be NULL.
 * @param opts Unused.
 * @return The requested codegen, or NULL if not found.
 */
static struct bf_cgen *_bf_ctx_get_nf_cgen(const bf_list *list,
                                           const struct bf_hook_opts *opts)
{
    UNUSED(opts);
    struct bf_list_node *node;

    bf_assert(list);

    node = bf_list_get_head(list);
    return node ? bf_list_node_get_data(node->data) : NULL;
}

static struct bf_cgen *_bf_ctx_get_cgroup_cgen(const bf_list *list,
                                               const struct bf_hook_opts *opts)
{
    bf_list_foreach (list, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        if (bf_streq(cgen->chain->hook_opts.cgroup, opts->cgroup))
            return cgen;
    }

    return NULL;
}

static struct bf_cgen *(*_bf_cgen_getters[])(
    const bf_list *list, const struct bf_hook_opts *opts) = {
    [BF_HOOK_XDP] = _bf_ctx_get_xdp_cgen,
    [BF_HOOK_TC_INGRESS] = _bf_ctx_get_xdp_cgen,
    [BF_HOOK_NF_PRE_ROUTING] = _bf_ctx_get_nf_cgen,
    [BF_HOOK_NF_LOCAL_IN] = _bf_ctx_get_nf_cgen,
    [BF_HOOK_CGROUP_INGRESS] = _bf_ctx_get_cgroup_cgen,
    [BF_HOOK_CGROUP_EGRESS] = _bf_ctx_get_cgroup_cgen,
    [BF_HOOK_NF_FORWARD] = _bf_ctx_get_nf_cgen,
    [BF_HOOK_NF_LOCAL_OUT] = _bf_ctx_get_nf_cgen,
    [BF_HOOK_NF_POST_ROUTING] = _bf_ctx_get_nf_cgen,
    [BF_HOOK_TC_EGRESS] = _bf_ctx_get_xdp_cgen,
};

static_assert(ARRAY_SIZE(_bf_cgen_getters) == _BF_HOOK_MAX,
              "missing entries in _bf_cgen_getters array");

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

    *ctx = malloc(sizeof(struct bf_ctx));
    if (!*ctx)
        return -ENOMEM;

    for (int i = 0; i < _BF_HOOK_MAX; ++i)
        (*ctx)->cgens[i] = bf_cgen_list();

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
    struct bf_marsh *list_elem = NULL;
    int i = 0;
    int r;

    bf_assert(ctx && marsh);

    r = _bf_ctx_new(&_ctx);
    if (r < 0)
        return r;

    // Unmarsh bf_ctx.cgens
    while ((list_elem = bf_marsh_next_child(marsh, list_elem))) {
        struct bf_marsh *cgen_elem = NULL;

        while ((cgen_elem = bf_marsh_next_child(list_elem, cgen_elem))) {
            _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;

            r = bf_cgen_new_from_marsh(&cgen, cgen_elem);
            if (r < 0)
                return r;

            r = bf_list_add_tail(&_ctx->cgens[i], cgen);
            if (r < 0)
                return r;

            TAKE_PTR(cgen);
        }

        ++i;
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

    for (int i = 0; i < _BF_HOOK_MAX; ++i)
        bf_list_clean(&(*ctx)->cgens[i]);

    freep((void *)ctx);
}

/**
 * See @ref bf_ctx_dump for details.
 */
static void _bf_ctx_dump(const struct bf_ctx *ctx, prefix_t *prefix)
{
    DUMP(prefix, "struct bf_ctx at %p", ctx);

    bf_dump_prefix_push(prefix);

    // Codegens
    DUMP(bf_dump_prefix_last(prefix), "cgens: bf_list[%d]", _BF_HOOK_MAX);
    bf_dump_prefix_push(prefix);

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        if (i == _BF_HOOK_MAX - 1)
            bf_dump_prefix_last(prefix);

        DUMP(prefix, "bf_list<bf_cgen>[%lu]", bf_list_size(&ctx->cgens[i]));
        bf_dump_prefix_push(prefix);

        bf_list_foreach (&ctx->cgens[i], cgen_node) {
            struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

            if (bf_list_is_tail(&ctx->cgens[i], cgen_node))
                bf_dump_prefix_last(prefix);

            bf_cgen_dump(cgen, prefix);
        }

        bf_dump_prefix_pop(prefix);
    }

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

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_list_marsh(&ctx->cgens[i], &child);
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
                                        enum bf_hook hook,
                                        const struct bf_hook_opts *opts)
{
    bf_assert(ctx);

    return _bf_cgen_getters[hook](&ctx->cgens[hook], opts);
}

/**
 * See @ref bf_ctx_set_cgen for details.
 */
static int _bf_ctx_set_cgen(struct bf_ctx *ctx, struct bf_cgen *cgen)
{
    bf_assert(ctx && cgen);

    if (_bf_ctx_get_cgen(ctx, cgen->chain->hook, &cgen->chain->hook_opts))
        return bf_err_r(-EEXIST, "codegen already exists in context");

    return bf_list_add_tail(&ctx->cgens[cgen->chain->hook], cgen);
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
            bf_list_foreach (&_bf_global_ctx->cgens[i], cgen_node)
                bf_cgen_unload(bf_list_node_get_data(cgen_node));
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

struct bf_cgen *bf_ctx_get_cgen(enum bf_hook hook,
                                const struct bf_hook_opts *opts)
{
    return _bf_ctx_get_cgen(_bf_global_ctx, hook, opts);
}

int bf_ctx_set_cgen(struct bf_cgen *cgen)
{
    return _bf_ctx_set_cgen(_bf_global_ctx, cgen);
}
