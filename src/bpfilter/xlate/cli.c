/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>

#include "bpfilter/cgen/cgen.h"
#include "bpfilter/cgen/prog/link.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/ctx.h"
#include "bpfilter/xlate/front.h"
#include "core/chain.h"
#include "core/counter.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"

static int _bf_cli_setup(void);
static int _bf_cli_teardown(void);
static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response);
static int _bf_cli_marsh(struct bf_marsh **marsh);
static int _bf_cli_unmarsh(struct bf_marsh *marsh);

const struct bf_front_ops cli_front = {
    .setup = _bf_cli_setup,
    .teardown = _bf_cli_teardown,
    .request_handler = _bf_cli_request_handler,
    .marsh = _bf_cli_marsh,
    .unmarsh = _bf_cli_unmarsh,
};

static int _bf_cli_setup(void)
{
    return 0;
}

static int _bf_cli_teardown(void)
{
    return 0;
}

int _bf_cli_ruleset_flush(const struct bf_request *request,
                          struct bf_response **response)
{
    UNUSED(request);
    UNUSED(response);

    bf_ctx_flush(BF_FRONT_CLI);

    return 0;
}

static int _bf_cli_ruleset_get(const struct bf_request *request,
                               struct bf_response **response)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *chain_marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *hookopts_marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *counters_marsh = NULL;
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    _clean_bf_list_ bf_list chains = bf_list_default(NULL, bf_chain_marsh);
    _clean_bf_list_ bf_list hookopts = bf_list_default(NULL, bf_hookopts_marsh);
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_list_free, bf_list_marsh);
    int r;

    UNUSED(request);

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to get new marsh");

    r = bf_ctx_get_cgens_for_front(&cgens, BF_FRONT_CLI);
    if (r < 0)
        return bf_err_r(r, "failed to get cgen list");

    bf_list_foreach (&cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);
        _cleanup_bf_list_ bf_list *cgen_counters = NULL;

        r = bf_list_add_tail(&chains, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to add chain to list");

        r = bf_list_add_tail(&hookopts, cgen->program->link->hookopts);
        if (r)
            return bf_err_r(r, "failed to add hookopts to list");

        r = bf_list_new(&cgen_counters, &bf_list_ops_default(bf_counter_free,
                                                             bf_counter_marsh));
        if (r)
            return r;

        r = bf_cgen_get_counters(cgen, cgen_counters);
        if (r)
            return r;

        r = bf_list_add_tail(&counters, cgen_counters);
        if (r)
            return r;

        TAKE_PTR(cgen_counters);
    }

    // Marsh the chain list
    r = bf_list_marsh(&chains, &chain_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to marshal chains list");

    r = bf_marsh_add_child_obj(&marsh, chain_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add chain list to marsh");

    // Marsh the hookopts list
    r = bf_marsh_new(&hookopts_marsh, NULL, 0);
    bf_list_foreach (&hookopts, hookopts_node) {
        struct bf_hookopts *hookopts = bf_list_node_get_data(hookopts_node);
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        if (hookopts) {
            r = bf_hookopts_marsh(bf_list_node_get_data(hookopts_node), &child);
            if (r < 0)
                return r;

            r = bf_marsh_add_child_obj(&hookopts_marsh, child);
            if (r < 0)
                return r;
        } else {
            r = bf_marsh_add_child_raw(&hookopts_marsh, NULL, 0);
            if (r)
                return r;
        }
    }

    r = bf_marsh_add_child_obj(&marsh, hookopts_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add chain list to marsh");

    // Marsh the counters list
    r = bf_list_marsh(&counters, &counters_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to marshal counters list");

    r = bf_marsh_add_child_obj(&marsh, counters_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add counters list to marsh");

    return bf_response_new_success(response, (void *)marsh,
                                   bf_marsh_size(marsh));
}

int _bf_cli_ruleset_set(const struct bf_request *request,
                        struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    struct bf_marsh *marsh, *list_elem = NULL;
    int r;

    bf_assert(request && response);

    // Unmarsh the list of chains
    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    bf_ctx_flush(BF_FRONT_CLI);

    while ((list_elem = bf_marsh_next_child(marsh, list_elem))) {
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        struct bf_marsh *child = NULL;

        child = bf_marsh_next_child(list_elem, child);
        if (!child)
            return bf_err_r(-ENOENT, "expecting marsh for chain, none found");

        r = bf_chain_new_from_marsh(&chain, child);
        if (r)
            goto err_load;

        child = bf_marsh_next_child(list_elem, child);
        if (!child)
            return bf_err_r(-ENOENT, "expecting marsh for hook, none found");
        if (child->data_len) {
            r = bf_hookopts_new_from_marsh(&hookopts, child);
            if (r)
                goto err_load;
        }

        r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
        if (r)
            goto err_load;

        r = bf_cgen_set(cgen, request->ns, hookopts ? &hookopts : NULL);
        if (r) {
            bf_err_r(r, "failed to set chain '%s'", cgen->chain->name);
            goto err_load;
        }

        r = bf_ctx_set_cgen(cgen);
        if (r) {
            /* The codegen is loaded already, if the daemon runs in persistent
             * mode, cleaning the codegen won't be sufficient to discard the
             * chain, it must be unpinned. */
            bf_cgen_unload(cgen);
            goto err_load;
        }

        TAKE_PTR(cgen);
    }

    return 0;

err_load:
    bf_ctx_flush(BF_FRONT_CLI);
    return r;
}

int _bf_cli_chain_set(const struct bf_request *request,
                      struct bf_response **response)
{
    struct bf_cgen *old_cgen;
    struct bf_marsh *marsh, *child = NULL;
    _cleanup_bf_cgen_ struct bf_cgen *new_cgen = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    int r;

    bf_assert(request && response);

    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return bf_err_r(-ENOENT, "expecting marsh for chain, none found");
    r = bf_chain_new_from_marsh(&chain, child);
    if (r)
        return r;

    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return bf_err_r(-ENOENT, "expecting marsh for hookopts, none found");
    if (child->data_len) {
        r = bf_hookopts_new_from_marsh(&hookopts, child);
        if (r)
            return r;
    }

    r = bf_cgen_new(&new_cgen, BF_FRONT_CLI, &chain);
    if (r)
        return r;

    old_cgen = bf_ctx_get_cgen(new_cgen->chain->name);
    if (old_cgen) {
        /* bf_ctx_delete_cgen() can only fail if the codegen is not found,
         * but we know this codegen exist. */
        (void)bf_ctx_delete_cgen(old_cgen, true);
    }

    r = bf_cgen_set(new_cgen, request->ns, hookopts ? &hookopts : NULL);
    if (r)
        return r;

    r = bf_ctx_set_cgen(new_cgen);
    if (r) {
        bf_cgen_unload(new_cgen);
        return r;
    }

    TAKE_PTR(new_cgen);

    return r;
}

static int _bf_cli_chain_get(const struct bf_request *request,
                             struct bf_response **response)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_counter_free, bf_counter_marsh);
    struct bf_cgen *cgen;
    struct bf_marsh *req_marsh, *child = NULL;
    int r;

    req_marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(req_marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    if (!(child = bf_marsh_next_child(req_marsh, child)))
        return -EINVAL;
    if (child->data_len < 2)
        return bf_err_r(-EINVAL, "_bf_cli_chain_get: chain name is empty");
    if (child->data[child->data_len - 1]) {
        return bf_err_r(-EINVAL,
                        "_bf_cli_chain_get: chain name if not nul-terminated");
    }

    cgen = bf_ctx_get_cgen(child->data);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' not found", req_marsh->data);

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to get new marsh");

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_chain_marsh(cgen->chain, &child);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r)
            return r;
    }

    if (cgen->program->link->hookopts) {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_hookopts_marsh(cgen->program->link->hookopts, &child);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r < 0)
            return r;
    } else {
        r = bf_marsh_add_child_raw(&marsh, NULL, 0);
        if (r)
            return r;
    }

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_cgen_get_counters(cgen, &counters);
        if (r)
            return r;

        r = bf_list_marsh(&counters, &child);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r)
            return r;
    }

    return bf_response_new_success(response, (void *)marsh,
                                   bf_marsh_size(marsh));
}

int _bf_cli_chain_load(const struct bf_request *request,
                       struct bf_response **response)
{
    struct bf_marsh *marsh, *child = NULL;
    _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    int r;

    bf_assert(request && response);

    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    bf_info("marsh=%p, child=%p", marsh, child);
    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return bf_err_r(-ENOENT, "expecting marsh for chain, none found");
    bf_info("chaib load unmarsh chain: %p", child);
    r = bf_chain_new_from_marsh(&chain, child);
    if (r)
        return r;

    if (bf_ctx_get_cgen(chain->name)) {
        return bf_err_r(-EEXIST,
                        "_bf_cli_chain_load: chain '%s' already exists",
                        chain->name);
    }

    r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
    if (r)
        return r;

    r = bf_cgen_load(cgen);
    if (r)
        return r;

    r = bf_ctx_set_cgen(cgen);
    if (r) {
        bf_cgen_unload(cgen);
        return bf_err_r(
            r, "bf_ctx_set_cgen: failed to add cgen to the runtime context");
    }

    TAKE_PTR(cgen);

    return r;
}

int _bf_cli_chain_attach(const struct bf_request *request,
                         struct bf_response **response)
{
    struct bf_marsh *marsh, *child = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen = NULL;
    const char *name;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    int r;

    bf_assert(request && response);

    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    if (marsh->data[marsh->data_len - 1]) {
        return bf_err_r(
            -EINVAL, "_bf_cli_chain_attach: chain name if not nul-terminated");
    }
    name = child->data;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    r = bf_hookopts_new_from_marsh(&hookopts, child);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(name);
    if (!cgen)
        return bf_err_r(-ENOENT, "chain '%s' does not exist", name);
    if (cgen->program->link->hookopts)
        return bf_err_r(-EBUSY, "chain '%s' is already linked to a hook", name);

    r = bf_hookopts_validate(hookopts, cgen->chain->hook);
    if (r)
        return bf_err_r(r, "failed to validate hook options");

    r = bf_cgen_attach(cgen, request->ns, &hookopts);
    if (r)
        return bf_err_r(r, "failed to attach codegen to hook");

    return r;
}

int _bf_cli_chain_update(const struct bf_request *request,
                         struct bf_response **response)
{
    struct bf_marsh *marsh, *child = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    struct bf_cgen *cgen = NULL;
    int r;

    bf_assert(request && response);

    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    child = bf_marsh_next_child(marsh, child);
    if (!child)
        return -EINVAL;
    r = bf_chain_new_from_marsh(&chain, child);
    if (r)
        return r;

    cgen = bf_ctx_get_cgen(chain->name);
    if (!cgen)
        return -ENOENT;

    if (!cgen->program->link->hookopts) {
        return bf_err_r(-EINVAL, "chain '%s' is not attached", chain->name);
    }

    r = bf_cgen_update(cgen, &chain);
    if (r)
        return -EINVAL;

    return r;
}

int _bf_cli_chain_flush(const struct bf_request *request,
                        struct bf_response **response)
{
    struct bf_marsh *marsh, *child = NULL;
    struct bf_cgen *cgen = NULL;

    bf_assert(request && response);

    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    if (child->data_len < 2)
        return bf_err_r(-EINVAL, "_bf_cli_chain_flush: chain name is empty");
    if (child->data[child->data_len - 1]) {
        return bf_err_r(
            -EINVAL, "_bf_cli_chain_flush: chain name if not nul-terminated");
    }

    cgen = bf_ctx_get_cgen(child->data);
    if (!cgen)
        return -ENOENT;

    return bf_ctx_delete_cgen(cgen, true);
}

static int _bf_cli_request_handler(struct bf_request *request,
                                   struct bf_response **response)
{
    int r;

    bf_assert(request);
    bf_assert(response);

    switch (request->cmd) {
    case BF_REQ_RULESET_FLUSH:
        r = _bf_cli_ruleset_flush(request, response);
        break;
    case BF_REQ_RULESET_SET:
        r = _bf_cli_ruleset_set(request, response);
        break;
    case BF_REQ_RULESET_GET:
        r = _bf_cli_ruleset_get(request, response);
        break;
    case BF_REQ_CHAIN_SET:
        r = _bf_cli_chain_set(request, response);
        break;
    case BF_REQ_CHAIN_GET:
        r = _bf_cli_chain_get(request, response);
        break;
    case BF_REQ_CHAIN_LOAD:
        r = _bf_cli_chain_load(request, response);
        break;
    case BF_REQ_CHAIN_ATTACH:
        r = _bf_cli_chain_attach(request, response);
        break;
    case BF_REQ_CHAIN_UPDATE:
        r = _bf_cli_chain_update(request, response);
        break;
    case BF_REQ_CHAIN_FLUSH:
        r = _bf_cli_chain_flush(request, response);
        break;
    default:
        r = bf_err_r(-EINVAL, "unsupported command %d for CLI front-end",
                     request->cmd);
        break;
    }

    /* If the callback don't need to send data back to the client, it can skip
     * the response creation and return a status code instead (0 on success,
     * negative errno value on error). The response is created based on the
     * status code. */
    if (!*response) {
        if (!r)
            r = bf_response_new_success(response, NULL, 0);
        else
            r = bf_response_new_failure(response, r);
    }

    return r;
}

static int _bf_cli_marsh(struct bf_marsh **marsh)
{
    UNUSED(marsh);

    return 0;
}

static int _bf_cli_unmarsh(struct bf_marsh *marsh)
{
    UNUSED(marsh);

    return 0;
}
