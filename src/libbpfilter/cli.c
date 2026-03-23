/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/ctx.h>

#include "bpfilter/chain.h"
#include "bpfilter/counter.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/list.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"
#include "bpfilter/set.h"
#include "cgen/cgen.h"
#include "cgen/handle.h"
#include "cgen/prog/link.h"
#include "cgen/prog/map.h"

static int copy_hookopts(struct bf_hookopts **dest,
                         const struct bf_hookopts *src)
{
    struct bf_hookopts *copy;

    copy = bf_memdup(src, sizeof(*src));
    if (!copy)
        return -ENOMEM;

    if (src->cgpath) {
        copy->cgpath = strdup(src->cgpath);
        if (!copy->cgpath) {
            free(copy);
            return -ENOMEM;
        }
    }

    *dest = copy;

    return 0;
}

int bf_ruleset_get(bf_list *chains, bf_list *hookopts, bf_list *counters)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    _clean_bf_list_ bf_list _chains = bf_list_default_from(*chains);
    _clean_bf_list_ bf_list _hookopts = bf_list_default_from(*hookopts);
    _clean_bf_list_ bf_list _counters = bf_list_default_from(*counters);
    int r;

    r = bf_ctx_get_cgens(&cgens);
    if (r < 0)
        return bf_err_r(r, "failed to get cgen list");

    bf_list_foreach (&cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
        _free_bf_list_ bf_list *cgen_counters = NULL;

        r = bf_chain_new_from_copy(&chain, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to copy chain");

        r = bf_list_add_tail(&_chains, chain);
        if (r)
            return r;
        TAKE_PTR(chain);

        if (cgen->handle->link && cgen->handle->link->hookopts) {
            r = copy_hookopts(&hookopts_copy, cgen->handle->link->hookopts);
            if (r)
                return bf_err_r(r, "failed to copy hookopts");
        }
        r = bf_list_add_tail(&_hookopts, hookopts_copy);
        if (r)
            return r;
        TAKE_PTR(hookopts_copy);

        r = bf_list_new(&cgen_counters,
                        &bf_list_ops_default(bf_counter_free, NULL));
        if (r)
            return r;

        r = bf_cgen_get_counters(cgen, cgen_counters);
        if (r)
            return r;

        r = bf_list_add_tail(&_counters, cgen_counters);
        if (r)
            return r;
        TAKE_PTR(cgen_counters);
    }

    *chains = bf_list_move(_chains);
    *hookopts = bf_list_move(_hookopts);
    *counters = bf_list_move(_counters);

    return 0;
}

int bf_ruleset_set(bf_list *chains, bf_list *hookopts)
{
    struct bf_list_node *chain_node = bf_list_get_head(chains);
    struct bf_list_node *hookopts_node = bf_list_get_head(hookopts);
    int r;

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;

    bf_ctx_flush();

    while (chain_node && hookopts_node) {
        _free_bf_cgen_ struct bf_cgen *cgen = NULL;
        _free_bf_chain_ struct bf_chain *chain_copy = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        struct bf_hookopts *node_hookopts =
            bf_list_node_get_data(hookopts_node);

        r = bf_chain_new_from_copy(&chain_copy, chain);
        if (r)
            goto err_load;

        if (node_hookopts) {
            r = copy_hookopts(&hookopts_copy, node_hookopts);
            if (r)
                goto err_load;
        }

        r = bf_cgen_new(&cgen, &chain_copy);
        if (r)
            goto err_load;

        r = bf_cgen_set(cgen, hookopts_copy ? &hookopts_copy : NULL);
        if (r) {
            bf_err_r(r, "failed to set chain '%s'", cgen->chain->name);
            goto err_load;
        }

        r = bf_ctx_set_cgen(cgen);
        if (r) {
            bf_cgen_unload(cgen);
            goto err_load;
        }

        TAKE_PTR(cgen);

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
    }

    return 0;

err_load:
    bf_ctx_flush();
    return r;
}

int bf_ruleset_flush(void)
{
    bf_ctx_flush();

    return 0;
}

int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts)
{
    struct bf_cgen *old_cgen;
    _free_bf_cgen_ struct bf_cgen *new_cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain_copy = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
    int r;

    assert(chain);

    r = bf_chain_new_from_copy(&chain_copy, chain);
    if (r)
        return r;

    if (hookopts) {
        r = copy_hookopts(&hookopts_copy, hookopts);
        if (r)
            return r;
    }

    r = bf_cgen_new(&new_cgen, &chain_copy);
    if (r)
        return r;

    old_cgen = bf_ctx_get_cgen(new_cgen->chain->name);
    if (old_cgen)
        (void)bf_ctx_delete_cgen(old_cgen, true);

    r = bf_cgen_set(new_cgen, hookopts_copy ? &hookopts_copy : NULL);
    if (r)
        return r;

    r = bf_ctx_set_cgen(new_cgen);
    if (r) {
        bf_cgen_unload(new_cgen);
        return r;
    }

    TAKE_PTR(new_cgen);

    return 0;
}

int bf_chain_get(const char *name, struct bf_chain **chain,
                 struct bf_hookopts **hookopts, bf_list *counters)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *_hookopts = NULL;
    _clean_bf_list_ bf_list _counters = bf_list_default_from(*counters);
    struct bf_cgen *cgen;
    int r;

    assert(name);
    assert(chain);
    assert(hookopts);
    assert(counters);

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' not found", name);

    r = bf_chain_new_from_copy(&_chain, cgen->chain);
    if (r)
        return r;

    if (cgen->handle->link && cgen->handle->link->hookopts) {
        r = copy_hookopts(&_hookopts, cgen->handle->link->hookopts);
        if (r)
            return r;
    }

    r = bf_cgen_get_counters(cgen, &_counters);
    if (r)
        return bf_err_r(r, "failed to get counters for '%s'", name);

    *chain = TAKE_PTR(_chain);
    *hookopts = TAKE_PTR(_hookopts);
    *counters = bf_list_move(_counters);

    return 0;
}

int bf_chain_prog_fd(const char *name)
{
    struct bf_cgen *cgen;

    if (!name)
        return -EINVAL;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "failed to find chain '%s'", name);

    if (cgen->handle->prog_fd == -1)
        return bf_err_r(-ENODEV, "chain '%s' has no loaded program", name);

    return dup(cgen->handle->prog_fd);
}

int bf_chain_logs_fd(const char *name)
{
    struct bf_cgen *cgen;

    if (!name)
        return -EINVAL;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "failed to find chain '%s'", name);

    if (!cgen->handle->lmap)
        return bf_err_r(-ENOENT, "chain '%s' has no logs buffer", name);

    return dup(cgen->handle->lmap->fd);
}

int bf_chain_load(struct bf_chain *chain)
{
    _free_bf_cgen_ struct bf_cgen *cgen = NULL;
    _free_bf_chain_ struct bf_chain *chain_copy = NULL;
    int r;

    assert(chain);

    if (bf_ctx_get_cgen(chain->name))
        return bf_err_r(-EEXIST, "chain '%s' already exists", chain->name);

    r = bf_chain_new_from_copy(&chain_copy, chain);
    if (r)
        return r;

    r = bf_cgen_new(&cgen, &chain_copy);
    if (r)
        return r;

    r = bf_cgen_load(cgen);
    if (r)
        return r;

    r = bf_ctx_set_cgen(cgen);
    if (r) {
        bf_cgen_unload(cgen);
        return bf_err_r(r, "failed to add cgen to the runtime context");
    }

    TAKE_PTR(cgen);

    return 0;
}

int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts)
{
    struct bf_cgen *cgen;
    _free_bf_hookopts_ struct bf_hookopts *hookopts_copy = NULL;
    int r;

    assert(name);
    assert(hookopts);

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", name);

    if (cgen->handle->link)
        return bf_err_r(-EBUSY, "chain '%s' is already linked to a hook", name);

    r = bf_hookopts_validate(hookopts, cgen->chain->hook);
    if (r)
        return bf_err_r(r, "failed to validate hook options");

    r = copy_hookopts(&hookopts_copy, hookopts);
    if (r)
        return r;

    r = bf_cgen_attach(cgen, &hookopts_copy);
    if (r)
        return bf_err_r(r, "failed to attach codegen to hook");

    return 0;
}

int bf_chain_update(const struct bf_chain *chain)
{
    _free_bf_chain_ struct bf_chain *chain_copy = NULL;
    struct bf_cgen *cgen;
    int r;

    assert(chain);

    cgen = bf_ctx_get_cgen(chain->name);
    if (!cgen)
        return -ENOENT;

    r = bf_chain_new_from_copy(&chain_copy, chain);
    if (r)
        return r;

    r = bf_cgen_update(cgen, &chain_copy, 0);
    if (r)
        return r;

    return 0;
}

static int copy_set(struct bf_set **dest, const struct bf_set *src)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    int r;

    r = bf_wpack_new(&wpack);
    if (r)
        return r;

    bf_wpack_open_object(wpack, "set");
    r = bf_set_pack(src, wpack);
    if (r)
        return r;
    bf_wpack_close_object(wpack);

    r = bf_wpack_get_data(wpack, &data, &data_len);
    if (r)
        return r;

    r = bf_rpack_new(&rpack, data, data_len);
    if (r)
        return r;

    bf_rpack_node_t child;
    r = bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &child);
    if (r)
        return r;

    return bf_set_new_from_pack(dest, child);
}

int bf_chain_update_set(const char *name, const struct bf_set *to_add,
                        const struct bf_set *to_remove)
{
    _free_bf_chain_ struct bf_chain *new_chain = NULL;
    struct bf_set *dest_set = NULL;
    struct bf_cgen *cgen;
    _free_bf_set_ struct bf_set *add_copy = NULL;
    _free_bf_set_ struct bf_set *remove_copy = NULL;
    int r;

    assert(name);
    assert(to_add);
    assert(to_remove);

    if (!bf_streq(to_add->name, to_remove->name))
        return bf_err_r(-EINVAL, "to_add->name must match to_remove->name");

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", name);

    r = bf_chain_new_from_copy(&new_chain, cgen->chain);
    if (r)
        return r;

    dest_set = bf_chain_get_set_by_name(new_chain, to_add->name);
    if (!dest_set)
        return bf_err_r(-ENOENT, "set '%s' does not exist", to_add->name);

    r = copy_set(&add_copy, to_add);
    if (r)
        return r;

    r = copy_set(&remove_copy, to_remove);
    if (r)
        return r;

    r = bf_set_add_many(dest_set, &add_copy);
    if (r)
        return bf_err_r(r, "failed to calculate set union");

    r = bf_set_remove_many(dest_set, &remove_copy);
    if (r)
        return bf_err_r(r, "failed to calculate set difference");

    r = bf_cgen_update(cgen, &new_chain,
                       BF_FLAG(BF_CGEN_UPDATE_PRESERVE_COUNTERS));
    if (r)
        return bf_err_r(r, "failed to update chain with new set data");

    return 0;
}

int bf_chain_flush(const char *name)
{
    struct bf_cgen *cgen;

    assert(name);

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return -ENOENT;

    return bf_ctx_delete_cgen(cgen, true);
}
