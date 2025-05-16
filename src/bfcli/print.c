/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/print.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/matcher.h"
#include "core/rule.h"
#include "core/verdict.h"

#define BF_DUMP_HEXDUMP_LEN 8
#define BF_DUMP_TOKEN_LEN 5

/**
 * Dump a block of memory in hexadecimal format.
 *
 * @param data Pointer to the data to be dumped. Must be non-NULL.
 * @param len Length of the data in bytes.
 */
static void bf_dump_hex_local(const void *data, size_t len)
{
    const void *end = data + len;
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];

    bf_assert(data);

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        (void)fprintf(stdout, "%s", buf);
    }
}

void bfc_chain_dump(struct bf_chain *chain, struct bf_hookopts *hookopts,
                    bf_list *counters)
{
    struct bf_counter *counter;
    bf_list_node *counter_node, *policy_counter_node, *err_counter_node;
    bool need_comma = false;

    bf_assert(chain && counters);

    if (bf_list_size(counters) != bf_list_size(&chain->rules) + 2) {
        bf_err(
            "chain %s is corrupted: total number of counters doesn't match the number of rules and chain counters",
            chain->name);
        return;
    }

    counter_node = bf_list_get_head(counters);
    policy_counter_node = bf_list_get_tail(counters);
    err_counter_node = bf_list_node_prev(policy_counter_node);

    (void)fprintf(stdout, "chain %s %s", chain->name,
                  bf_hook_to_str(chain->hook));
    if (hookopts) {
        (void)fprintf(stdout, "{");

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_IFINDEX)) {
            (void)fprintf(stdout, "%sifindex=%d", need_comma ? "," : "",
                          hookopts->ifindex);
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_CGPATH)) {
            (void)fprintf(stdout, "%scgpath=%s", need_comma ? "," : "",
                          hookopts->cgpath);
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_FAMILY)) {
            (void)fprintf(stdout, "%sfamily=%s", need_comma ? "," : "",
                          hookopts->family == PF_INET ? "inet4" : "inet6");
            need_comma = true;
        }

        if (bf_hookopts_is_used(hookopts, BF_HOOKOPTS_FAMILY)) {
            (void)fprintf(stdout, "%spriorities=%d-%d", need_comma ? "," : "",
                          hookopts->priorities[0], hookopts->priorities[1]);
            need_comma = true;
        }

        (void)fprintf(stdout, "}");
    }

    (void)fprintf(stdout, " %s\n", bf_verdict_to_str(chain->policy));

    counter = bf_list_node_get_data(policy_counter_node);
    (void)fprintf(stdout, "    counters policy %lu packets %lu bytes; ",
                  counter->packets, counter->bytes);

    counter = bf_list_node_get_data(err_counter_node);
    (void)fprintf(stdout, "error %lu packets %lu bytes\n", counter->packets,
                  counter->bytes);

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        (void)fprintf(stdout, "    rule\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            (void)fprintf(stdout, "        %s",
                          bf_matcher_type_to_str(matcher->type));
            (void)fprintf(stdout, " %s ", bf_matcher_op_to_str(matcher->op));

            bf_dump_hex_local(matcher->payload,
                              matcher->len - sizeof(struct bf_matcher));
            (void)fprintf(stdout, "\n");
        }

        counter = bf_list_node_get_data(counter_node);
        (void)fprintf(stdout, "        counters %lu packets %lu bytes\n",
                      counter->packets, counter->bytes);
        counter_node = bf_list_node_next(counter_node);

        (void)fprintf(stdout, "        %s\n", bf_verdict_to_str(rule->verdict));
    }
}

int bfc_ruleset_dump(bf_list *chains, bf_list *hookopts, bf_list *counters)
{
    struct bf_list_node *chain_node;
    struct bf_list_node *hookopts_node;
    struct bf_list_node *counter_node;

    bf_assert(chains && hookopts && counters);

    if (bf_list_size(chains) != bf_list_size(hookopts))
        return -EINVAL;
    if (bf_list_size(counters) != bf_list_size(chains))
        return -EINVAL;

    chain_node = bf_list_get_head(chains);
    hookopts_node = bf_list_get_head(hookopts);
    counter_node = bf_list_get_head(counters);

    while (chain_node) {
        bfc_chain_dump(bf_list_node_get_data(chain_node),
                       bf_list_node_get_data(hookopts_node),
                       bf_list_node_get_data(counter_node));

        chain_node = bf_list_node_next(chain_node);
        hookopts_node = bf_list_node_next(hookopts_node);
        counter_node = bf_list_node_next(counter_node);
    }

    return 0;
}
