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

#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
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

/**
 * Dump the details of a chain, including its rules and counters.
 *
 * @param chain Chain to be dumped. Can't be NULL.
 * @param ctr_node A node in the counter list. Can be NULL if no
 *                 chains are loaded, or not printing counters.
 * @param with_counters Boolean flag indicating whether to include
 *        counters in the dump.
 */
static int bf_cli_chain_dump(struct bf_chain *chain,
                             struct bf_list_node **ctr_node, bool with_counters)
{
    struct bf_hook_opts *opts = &chain->hook_opts;
    struct bf_counter *counter = NULL;
    uint32_t used_opts = chain->hook_opts.used_opts;
    bool need_comma = false;

    bf_assert(chain);
    bf_assert(!with_counters || *ctr_node);

    (void)fprintf(stdout, "chain %s", bf_hook_to_str(chain->hook));
    (void)fprintf(stdout, "{");

    if (used_opts & (1 << BF_HOOK_OPT_ATTACH)) {
        (void)fprintf(stdout, "attach=%s", opts->attach ? "yes" : "no");
        need_comma = true;
    }

    if (used_opts & (1 << BF_HOOK_OPT_IFINDEX)) {
        (void)fprintf(stdout, "%sifindex=%d", need_comma ? "," : "",
                      opts->ifindex);
        need_comma = true;
    }

    if (used_opts & (1 << BF_HOOK_OPT_NAME)) {
        (void)fprintf(stdout, "%sname=%s", need_comma ? "," : "", opts->name);
        need_comma = true;
    }

    (void)fprintf(stdout, "}");
    (void)fprintf(stdout, " policy %s\n", bf_verdict_to_str(chain->policy));

    if (with_counters) {
        /*
         * Counter list order (from daemon) is Error, Policy, Rules.
         * Desired print order is Policy, Error, and then Rules.
        */
        struct bf_list_node *error_node = *ctr_node;

        *ctr_node = bf_list_node_next(*ctr_node);
        if (!*ctr_node)
            return bf_err_r(-ENOENT,
                            "expected policy counter, not end of list");

        // Print the policy counter
        counter = bf_list_node_get_data(*ctr_node);
        if (!counter)
            return bf_err_r(-ENOENT, "got NULL pointer for policy counter");

        (void)fprintf(stdout, "    counters policy %lu packets %lu bytes; ",
                      counter->packets, counter->bytes);

        // Print the error counter
        counter = (struct bf_counter *)bf_list_node_get_data(error_node);
        if (!counter)
            return bf_err_r(-ENOENT, "got NULL pointer for error counter");
        (void)fprintf(stdout, "error %lu packets %lu bytes\n", counter->packets,
                      counter->bytes);

        /*
         * Next is a rule counter, or a policy counter of the next chain,
         * or NULL for the end of the list.
        */
        *ctr_node = bf_list_node_next(*ctr_node);
    }

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

        // Print the counters and remove the head
        if (with_counters) {
            // ctr_node should be pointing to the rule counter
            if (!*ctr_node)
                return bf_err_r(-ENOENT,
                                "expected rule counter, not end of list");

            counter = (struct bf_counter *)bf_list_node_get_data(*ctr_node);
            if (!counter)
                return bf_err_r(-ENOENT, "got NULL pointer for rule counter");

            (void)fprintf(stdout, "        counters %lu packets %lu bytes\n",
                          counter->packets, counter->bytes);
            /*
             * Next is a rule counter, or a policy counter of the next chain,
             * or NULL for the end of the list.
            */
            *ctr_node = bf_list_node_next(*ctr_node);
        }

        (void)fprintf(stdout, "        %s\n", bf_verdict_to_str(rule->verdict));
    }

    (void)fprintf(stdout, "\n");

    return 0;
}

int bf_cli_dump_ruleset(bf_list *chains, bf_list *counters, bool with_counters)
{
    struct bf_list_node *ctr_node = NULL;
    int r;

    bf_assert(chains);
    bf_assert(!with_counters || counters);

    // ctr_node may be NULL if no chains are loaded
    if (with_counters)
        ctr_node = bf_list_get_head(counters);

    // Print all chains
    bf_list_foreach (chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        r = bf_cli_chain_dump(chain, &ctr_node, with_counters);
        if (r < 0)
            return bf_err_r(r, "failed to dump chain");
    }

    return 0;
}
