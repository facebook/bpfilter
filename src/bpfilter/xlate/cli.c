/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>

#include "bpfilter/cgen/cgen.h"
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

/**
 * Get a list of counters (chain and rule) for all cgens
 * in the input list.
 *
 * @param cgens A list of code generators. Can't be NULL.
 * @param counters A list of counters. Can't be NULL.
 * @return 0 on success or negative error code on failure.
 */
static int _bf_cli_get_counters(const bf_list *cgens, bf_list *counters)
{
    _clean_bf_list_ bf_list _counters =
        bf_list_default(counters->ops.free, counters->ops.marsh);
    int r;

    bf_assert(cgens && counters);

    bf_list_foreach (cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);

        for (ssize_t i = -2; i < (ssize_t)bf_list_size(&cgen->chain->rules);
             ++i) {
            _cleanup_bf_counter_ struct bf_counter *counter = NULL;

            r = bf_counter_new(&counter, 0, 0);
            if (r)
                return r;

            r = bf_cgen_get_counter(cgen, i, counter);
            if (r)
                return r;

            r = bf_list_add_tail(&_counters, counter);
            if (r)
                return r;

            TAKE_PTR(counter);
        }
    }

    *counters = bf_list_move(_counters);

    return 0;
}

static int _bf_cli_ruleset_get(const struct bf_request *request,
                               struct bf_response **response)
{
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *chain_marsh = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *counters_marsh = NULL;
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    _clean_bf_list_ bf_list chains = bf_list_default(NULL, bf_chain_marsh);
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_counter_free, bf_counter_marsh);
    int r;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to get new marsh");

    r = bf_ctx_get_cgens_for_front(&cgens, BF_FRONT_CLI);
    if (r < 0)
        return bf_err_r(r, "failed to get cgen list");

    bf_list_foreach (&cgens, cgen_node) {
        struct bf_cgen *cgen = bf_list_node_get_data(cgen_node);
        r = bf_list_add_tail(&chains, cgen->chain);
        if (r)
            return bf_err_r(r, "failed to add chain to list");
    }

    if (request->cli_with_counters) {
        r = _bf_cli_get_counters(&cgens, &counters);
        if (r)
            return bf_err_r(r, "failed to get counters list");
    }

    // Marsh the chain list
    r = bf_list_marsh(&chains, &chain_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to marshal list");

    r = bf_marsh_add_child_obj(&marsh, chain_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add chain list to marsh");

    r = bf_list_marsh(&counters, &counters_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to marshal list");

    r = bf_marsh_add_child_obj(&marsh, counters_marsh);
    if (r < 0)
        return bf_err_r(r, "failed to add chain list to marsh");

    return bf_response_new_success(response, (void *)marsh,
                                   bf_marsh_size(marsh));
}

int _bf_cli_ruleset_set(const struct bf_request *request,
                        struct bf_response **response)
{
    _clean_bf_list_ bf_list cgens = bf_list_default(NULL, NULL);
    struct bf_marsh *marsh, *child = NULL;
    int r = 0;

    bf_assert(request && response);

    // Unmarsh the list of chains
    marsh = (struct bf_marsh *)request->data;
    if (bf_marsh_size(marsh) != request->data_len) {
        return bf_err_r(
            -EINVAL,
            "request payload is expected to have the same size as the marsh");
    }

    bf_ctx_flush(BF_FRONT_CLI);

    while ((child = bf_marsh_next_child(marsh, child))) {
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;
        _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
        struct bf_marsh *cchild = NULL;

        cchild = bf_marsh_next_child(child, cchild);
        if (!cchild)
            return bf_err_r(-ENOENT, "expecting marsh for chain, none found");

        r = bf_chain_new_from_marsh(&chain, cchild);
        if (r)
            goto err_load;

        cchild = bf_marsh_next_child(child, cchild);
        if (!cchild)
            return bf_err_r(-ENOENT, "expecting marsh for hook, none found");

        if (cchild->data_len) {
            r = bf_hookopts_new_from_marsh(&hookopts, cchild);
            if (r)
                goto err_load;
        }

        r = bf_cgen_new(&cgen, BF_FRONT_CLI, &chain);
        if (r)
            goto err_load;

        r = bf_cgen_load(cgen);
        if (r)
            goto err_load;

        if (hookopts) {
            r = bf_cgen_attach(cgen, request->ns, hookopts);
            if (r)
                goto err_load;
        }

        r = bf_ctx_set_cgen(cgen);
        if (r) {
            bf_err("failed to add cgen to the runtime context");
            goto err_load;
        }

        r = bf_list_add_tail(&cgens, cgen);
        if (r)
            goto err_load;

        TAKE_PTR(cgen);
    }

    return r;

err_load:
    bf_list_foreach (&cgens, cgen_node)
        bf_ctx_delete_cgen(bf_list_node_get_data(cgen_node), true);

    return r;
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
