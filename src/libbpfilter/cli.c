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
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"
#include "libbpfilter/generic.h"

int bf_cli_ruleset_get(bf_list *chains, bf_list *counters, bool with_counters)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    _clean_bf_list_ bf_list _chains = bf_list_default(bf_chain_free, NULL);
    _clean_bf_list_ bf_list _counters = bf_list_default(bf_counter_free, NULL);
    struct bf_marsh *marsh = NULL;
    struct bf_marsh *child = NULL;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULESET_GET;
    request->cli_with_counters = with_counters;

    r = bf_send(request, &response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if (response->type == BF_RES_FAILURE)
        return response->error;

    if (response->data_len == 0) {
        bf_info("no ruleset returned");
        return 0;
    }

    marsh = (struct bf_marsh *)response->data;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    {
        // Unmarsh chains
        struct bf_marsh *elem = NULL;

        while ((elem = bf_marsh_next_child(child, elem))) {
            _cleanup_bf_chain_ struct bf_chain *chain = NULL;
            r = bf_chain_new_from_marsh(&chain, elem);
            if (r < 0)
                return r;

            r = bf_list_add_tail(&_chains, chain);
            if (r < 0)
                return r;

            TAKE_PTR(chain);
        }
    }

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    {
        // Unmarsh counters
        struct bf_marsh *elem = NULL;

        while ((elem = bf_marsh_next_child(child, elem))) {
            _cleanup_bf_counter_ struct bf_counter *counter = NULL;

            r = bf_counter_new_from_marsh(&counter, elem);
            if (r < 0)
                return r;

            r = bf_list_add_tail(&_counters, counter);
            if (r < 0)
                return r;

            TAKE_PTR(counter);
        }
    }

    *chains = bf_list_move(_chains);
    if (with_counters)
        *counters = bf_list_move(_counters);

    return 0;
}

int bf_cli_ruleset_flush(void)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
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

int bf_cli_set_chain(const struct bf_chain *chain)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;
    int r;

    r = bf_chain_marsh(chain, &marsh);
    if (r)
        return bf_err_r(r, "failed to marsh chain");

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
