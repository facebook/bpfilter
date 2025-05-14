/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

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
#include "libbpfilter/generic.h"

int bf_cli_ruleset_get(bf_list *chains, bf_list *hookopts, bf_list *counters)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _clean_bf_list_ bf_list _chains = bf_list_default_from(*chains);
    _clean_bf_list_ bf_list _hookopts = bf_list_default_from(*hookopts);
    _clean_bf_list_ bf_list _counters = bf_list_default_from(*counters);
    struct bf_marsh *marsh = NULL;
    struct bf_marsh *child = NULL;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_GET;

    r = bf_send(request, &response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if (response->type == BF_RES_FAILURE)
        return response->error;

    if (response->data_len == 0)
        return 0;

    marsh = (struct bf_marsh *)response->data;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    for (struct bf_marsh *schild = bf_marsh_next_child(child, NULL); schild;
         schild = bf_marsh_next_child(child, schild)) {
        _free_bf_chain_ struct bf_chain *chain = NULL;

        r = bf_chain_new_from_marsh(&chain, schild);
        if (r)
            return r;

        r = bf_list_add_tail(&_chains, chain);
        if (r)
            return r;

        TAKE_PTR(chain);
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    for (struct bf_marsh *schild = bf_marsh_next_child(child, NULL); schild;
         schild = bf_marsh_next_child(child, schild)) {
        _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;

        if (!bf_marsh_is_empty(schild)) {
            r = bf_hookopts_new_from_marsh(&hookopts, schild);
            if (r)
                return r;
        }

        r = bf_list_add_tail(&_hookopts, hookopts);
        if (r)
            return r;

        TAKE_PTR(hookopts);
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    for (struct bf_marsh *schild = bf_marsh_next_child(child, NULL); schild;
         schild = bf_marsh_next_child(child, schild)) {
        _free_bf_list_ bf_list *nested = NULL;

        r = bf_list_new(
            &nested, &bf_list_ops_default(bf_counter_free, bf_counter_marsh));
        if (r)
            return r;

        for (struct bf_marsh *counter_marsh = bf_marsh_next_child(schild, NULL);
             counter_marsh;
             counter_marsh = bf_marsh_next_child(schild, counter_marsh)) {
            _free_bf_counter_ struct bf_counter *counter = NULL;

            r = bf_counter_new_from_marsh(&counter, counter_marsh);
            if (r)
                return r;

            r = bf_list_add_tail(nested, counter);
            if (r)
                return r;

            TAKE_PTR(counter);
        }

        r = bf_list_add_tail(&_counters, nested);
        if (r)
            return r;

        TAKE_PTR(nested);
    }

    *chains = bf_list_move(_chains);
    *hookopts = bf_list_move(_hookopts);
    *counters = bf_list_move(_counters);

    return 0;
}

int bf_cli_ruleset_flush(void)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r)
        return bf_err_r(r, "failed to create a ruleset flush request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_FLUSH;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send a ruleset flush request");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_cli_ruleset_set(bf_list *chains, bf_list *hookopts)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;
    struct bf_list_node *chain_node = bf_list_get_head(chains);
    struct bf_list_node *hookopts_node = bf_list_get_head(hookopts);
    int r;

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r)
        return r;

    while (chain_node && hookopts_node) {
        _free_bf_marsh_ struct bf_marsh *chain_marsh = NULL;
        _free_bf_marsh_ struct bf_marsh *hook_marsh = NULL;
        _free_bf_marsh_ struct bf_marsh *_marsh = NULL;
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        struct bf_hookopts *hookopts = bf_list_node_get_data(hookopts_node);

        r = bf_marsh_new(&_marsh, NULL, 0);
        if (r)
            return r;

        r = bf_chain_marsh(chain, &chain_marsh);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, chain_marsh);
        if (r)
            return r;

        if (hookopts) {
            r = bf_hookopts_marsh(hookopts, &hook_marsh);
            if (r)
                return r;

            r = bf_marsh_add_child_obj(&_marsh, hook_marsh);
            if (r)
                return r;
        } else {
            r = bf_marsh_add_child_raw(&_marsh, NULL, 0);
            if (r)
                return r;
        }

        r = bf_marsh_add_child_obj(&marsh, _marsh);
        if (r)
            return r;

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
    }

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "failed to create request for chain");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_SET;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_chain_set(struct bf_chain *chain, struct bf_hookopts *hookopts)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;
    _free_bf_marsh_ struct bf_marsh *chain_marsh = NULL;
    _free_bf_marsh_ struct bf_marsh *hook_marsh = NULL;
    int r;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r)
        return r;

    r = bf_chain_marsh(chain, &chain_marsh);
    if (r)
        return r;

    r = bf_marsh_add_child_obj(&marsh, chain_marsh);
    if (r)
        return r;

    if (hookopts) {
        r = bf_hookopts_marsh(hookopts, &hook_marsh);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&marsh, hook_marsh);
        if (r)
            return r;
    } else {
        r = bf_marsh_add_child_raw(&marsh, NULL, 0);
        if (r)
            return r;
    }

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "bf_chain_set: failed to create request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_SET;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_set: failed to send request");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_chain_get(const char *name, struct bf_chain **chain,
                 struct bf_hookopts **hookopts, bf_list *counters)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *_hookopts = NULL;
    _clean_bf_list_ bf_list _counters = bf_list_default_from(*counters);
    struct bf_marsh *marsh, *child = NULL;
    _free_bf_marsh_ struct bf_marsh *req_marsh = NULL;
    int r;

    r = bf_marsh_new(&req_marsh, NULL, 0);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&req_marsh, name, strlen(name) + 1);
    if (r)
        return r;

    r = bf_request_new(&request, req_marsh, bf_marsh_size(req_marsh));
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_GET;

    r = bf_send(request, &response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if (response->type == BF_RES_FAILURE)
        return response->error;

    marsh = (struct bf_marsh *)response->data;
    if (bf_marsh_size(marsh) != response->data_len) {
        return bf_err_r(
            -EINVAL,
            "response payload is expected to have the same size as the marsh");
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    r = bf_chain_new_from_marsh(&_chain, child);
    if (r)
        return r;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    if (child->data_len) {
        r = bf_hookopts_new_from_marsh(&_hookopts, child);
        if (r)
            return r;
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    for (struct bf_marsh *counter_marsh = bf_marsh_next_child(child, NULL);
         counter_marsh;
         counter_marsh = bf_marsh_next_child(child, counter_marsh)) {
        _free_bf_counter_ struct bf_counter *counter = NULL;

        r = bf_counter_new_from_marsh(&counter, counter_marsh);
        if (r)
            return r;

        r = bf_list_add_tail(&_counters, counter);
        if (r)
            return r;

        TAKE_PTR(counter);
    }

    *chain = TAKE_PTR(_chain);
    *hookopts = TAKE_PTR(_hookopts);
    *counters = bf_list_move(_counters);

    return 0;
}

int bf_chain_load(struct bf_chain *chain)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;
    int r;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r)
        return r;

    {
        _free_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_chain_marsh(chain, &child);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r)
            return r;
    }

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "bf_chain_load: failed to create a new request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_LOAD;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_set: failed to send request");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_chain_attach(const char *name, const struct bf_hookopts *hookopts)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;
    int r;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&marsh, name, strlen(name) + 1);
    if (r)
        return r;

    {
        _free_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_hookopts_marsh(hookopts, &child);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&marsh, child);
        if (r)
            return r;
    }

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "bf_chain_attach: failed to create a new request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_ATTACH;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_attach: failed to send request");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_chain_update(const struct bf_chain *chain)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;
    _free_bf_marsh_ struct bf_marsh *child = NULL;
    int r;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r)
        return r;

    r = bf_chain_marsh(chain, &child);
    if (r)
        return r;

    r = bf_marsh_add_child_obj(&marsh, child);
    if (r)
        return r;

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "bf_chain_update: failed to create a new request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_UPDATE;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "bf_chain_update: failed to send request");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}

int bf_chain_flush(const char *name)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_marsh_ struct bf_marsh *marsh = NULL;
    int r;

    r = bf_marsh_new(&marsh, NULL, 0);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&marsh, name, strlen(name) + 1);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&marsh, name, strlen(name) + 1);
    if (r)
        return r;

    r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
    if (r)
        return bf_err_r(r, "failed to create request for chain");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_CHAIN_FLUSH;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}
