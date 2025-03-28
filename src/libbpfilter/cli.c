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

static int
bf_cli_get_chains_and_counters(bf_list *chains, bf_list *counters,
                               struct bf_marsh *chains_and_counters_marsh)
{
    struct bf_marsh *chains_marsh, *chain_marsh = NULL, *counters_marsh;
    struct bf_marsh *child = NULL;
    int r;

    // Get the chain list
    chains_marsh = bf_marsh_next_child(chains_and_counters_marsh, NULL);
    if (!chains_marsh) {
        bf_err("failed to locate chain list from daemon response\n");
        return -EINVAL;
    }

    // Get the marshaled list of counters
    counters_marsh =
        bf_marsh_next_child(chains_and_counters_marsh, chains_marsh);
    if (!counters_marsh) {
        bf_err("failed to locate counter array from daemon response\n");
        return -EINVAL;
    }

    while (true) {
        _cleanup_bf_counter_ struct bf_counter *counter = NULL;

        // Get the next child
        child = bf_marsh_next_child(counters_marsh, child);
        if (!child) {
            break;
        }

        r = bf_counter_new_from_marsh(&counter, child);
        if (r < 0)
            return bf_err_r(r, "failed to unmarsh counter");

        r = bf_list_add_tail(counters, counter);
        TAKE_PTR(counter);
    }

    // Loop over the chains
    while (true) {
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;

        // Get the next child
        chain_marsh = bf_marsh_next_child(chains_marsh, chain_marsh);
        if (!chain_marsh)
            break;

        r = bf_chain_new_from_marsh(&chain, chain_marsh);
        if (r < 0)
            return bf_err_r(r, "failed to unmarsh chain");

        // Add the chain to the list
        r = bf_list_add_tail(chains, chain);
        if (r < 0)
            return bf_err_r(r, "failed to add chain to list");

        TAKE_PTR(chain);
    }

    return 0;
}

int bf_cli_ruleset_get(bf_list *chains, bf_list *counters, bool with_counters)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULES_GET;
    request->cli_with_counters = with_counters;

    r = bf_send(request, &response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if (response->type == BF_RES_FAILURE)
        return response->error;

    if (response->data_len == 0) {
        bf_info("no ruleset returned\n");
        return 0;
    }

    bf_cli_get_chains_and_counters(chains, counters,
                                   (struct bf_marsh *)response->data);

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
    request->cmd = BF_REQ_RULES_SET;

    r = bf_send(request, &response);
    if (r)
        return bf_err_r(r, "failed to send chain to the daemon");

    return response->type == BF_RES_FAILURE ? response->error : 0;
}
