/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>
#include <string.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/rule.h"
#include "libbpfilter/generic.h"

// TODO: Obviously resolve this duplication of bf_dump_hex
#define BF_DUMP_HEXDUMP_LEN 8
#define BF_DUMP_TOKEN_LEN 5

static void bf_dump_hex_local(const void *data, size_t len)
{
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];
    const void *end = data + len;

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        // NOLINTNEXTLINE
        fprintf(stderr, "%s", buf);
    }
}

// TODO: Sort out our use of fprintf vs DUMP
// NOLINTBEGIN
static void bf_cli_chain_dump(struct bf_chain *chain, bool with_counters,
                              struct bf_counter **counter)
{
    // Dump chain info
    fprintf(stderr, "chain %s", bf_hook_to_str(chain->hook));
    fprintf(stderr, "{");

    struct bf_hook_opts *opts = &chain->hook_opts;

    // Ignore unused
    fprintf(stderr, "attach=%s,", opts->attach ? "yes" : "no");
    fprintf(stderr, "ifindex=%d", opts->ifindex);
    if (opts->name)
        fprintf(stderr, ",name=%s", opts->name);
    fprintf(stderr, "}");
    fprintf(stderr, " policy: %s\n", bf_verdict_to_str(chain->policy));

    if (with_counters) {
        // Policy counter is the first one after the rules; error counter follows it.
        struct bf_counter *chain_counter =
            *counter + bf_list_size(&chain->rules);
        fprintf(stderr, "\tcounters: policy %lu bytes %lu packets; ",
                chain_counter->bytes, chain_counter->packets);

        chain_counter++;

        fprintf(stderr, "error %lu bytes %lu packets\n", chain_counter->bytes,
                chain_counter->packets);
    }

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        fprintf(stderr, "\trule: %d\n", rule->index);
        // Matchers
        fprintf(stderr, "\t\tmatcher(s):\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            fprintf(stderr, "\t\t\t\%s", bf_matcher_type_to_str(matcher->type));
            fprintf(stderr, " %s ", bf_matcher_op_to_str(matcher->op));

            bf_opts_set_verbose(BF_VERBOSE_DEBUG);
            bf_dump_hex_local(matcher->payload,
                              matcher->len - sizeof(struct bf_matcher));
            fprintf(stderr, "\n");
        }
        // remove yes no print, make this conditional
        if (with_counters && rule->counters) {
            fprintf(stderr, "\t\tcounters: %lu bytes %lu packets\n",
                    (*counter)->bytes, (*counter)->packets);
            (*counter)++;
        }

        fprintf(stderr, "\t\tverdict: %s\n", bf_verdict_to_str(rule->verdict));
    }

    // Skip over the policy and error counters
    (*counter) += 2;

    fprintf(stderr, "\n");
}

// NOLINTEND

static int bf_cli_request_ruleset(struct bf_response **response,
                                  bool with_counters)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    int r;

    r = bf_request_new(&request, NULL, 0);
    if (r < 0)
        return bf_err_r(r, "failed to init request");

    request->front = BF_FRONT_CLI;
    request->cmd = BF_REQ_RULES_GET;
    request->with_counters = with_counters;

    r = bf_send(request, response);
    if (r < 0)
        return bf_err_r(r, "failed to send a ruleset get request");

    if ((*response)->type == BF_RES_FAILURE)
        return (*response)->error;

    return 0;
}

static int bf_cli_dump_ruleset(struct bf_marsh *chains_marsh,
                               struct bf_marsh *counters_marsh,
                               bool with_counters)
{
    bf_assert(chains_marsh);
    bf_assert(counters_marsh);

    struct bf_counter *counters = (struct bf_counter *)counters_marsh->data;
    struct bf_marsh *chain_marsh = NULL;
    int r;

    // Loop over the chains
    while (true) {
        // Get the next child
        chain_marsh = bf_marsh_next_child(chains_marsh, chain_marsh);
        if (!chain_marsh) {
            break;
        }

        _cleanup_bf_chain_ struct bf_chain *chain = NULL;
        r = bf_chain_new_from_marsh(&chain, chain_marsh);
        if (r < 0)
            return bf_err_r(r, "failed to unmarsh chain");

        bf_cli_chain_dump(chain, with_counters, &counters);
    }

    return 0;
}

int bf_cli_ruleset_get(bool with_counters)
{
    int r;

    _cleanup_bf_response_ struct bf_response *response = NULL;
    r = bf_cli_request_ruleset(&response, with_counters);
    if (r < 0)
        return bf_err_r(r, "failed to request ruleset\n");

    if (response->type == BF_RES_FAILURE)
        return bf_err_r(response->error, "failed to get ruleset\n");

    if (response->data_len == 0) {
        // NOLINTNEXTLINE
        fprintf(stderr, "no ruleset returned\n");
        return 0;
    }

    struct bf_marsh *chains_and_counters_marsh =
        (struct bf_marsh *)response->data;

    // Get the chain list
    struct bf_marsh *chains_marsh =
        bf_marsh_next_child(chains_and_counters_marsh, NULL);
    if (!chains_marsh) {
        bf_err("failed to locate chain list from daemon response\n");
    }

    // Get the array of counters
    struct bf_marsh *counters_marsh =
        bf_marsh_next_child(chains_and_counters_marsh, chains_marsh);
    if (!counters_marsh) {
        bf_err("failed to locate counter array from daemon response\n");
    }

    return bf_cli_dump_ruleset(chains_marsh, counters_marsh, with_counters);
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
