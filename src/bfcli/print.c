/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "print.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
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
    bf_assert(data);
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];
    const void *end = data + len;

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        (void)fprintf(stderr, "%s", buf);
    }
}

/**
 * Dump the details of a chain, including its rules and counters.
 *
 * @param chain Pointer to the chain to be dumped. Must be non-NULL.
 * @param counter Pointer to the array of counters associated with the
 *        chain. Must be non-NULL if with_counters is true.
 * @param with_counters Boolean flag indicating whether to include
 *        counters in the dump.
 */
static int bf_cli_chain_dump(struct bf_chain *chain, bf_list *counters,
                             bool with_counters)
{
    struct bf_hook_opts *opts = &chain->hook_opts;
    struct bf_counter *counter = NULL;

    bf_assert(chain);
    bf_assert(!with_counters || counters);

    (void)fprintf(stderr, "chain %s", bf_hook_to_str(chain->hook));
    (void)fprintf(stderr, "{");

    (void)fprintf(stderr, "attach=%s,", opts->attach ? "yes" : "no");
    (void)fprintf(stderr, "ifindex=%d", opts->ifindex);
    if (opts->name)
        (void)fprintf(stderr, ",name=%s", opts->name);
    (void)fprintf(stderr, "}");
    (void)fprintf(stderr, " policy: %s\n", bf_verdict_to_str(chain->policy));

    if (with_counters) {
        /**
         * Rule counters are followed by policy and error counters.
         * These bf_list_get_at() calls cost linear time.
        */
        counter = (struct bf_counter *)bf_list_get_at(
            counters, bf_list_size(&chain->rules));
        if (!counter) {
            return bf_err_r(-ENOENT, "got null policy counter\n");
        }

        (void)fprintf(stderr, "\tcounters: policy %lu bytes %lu packets; ",
                      counter->bytes, counter->packets);

        counter = (struct bf_counter *)bf_list_get_at(
            counters, bf_list_size(&chain->rules) + 1);
        if (!counter) {
            return bf_err_r(-ENOENT, "got null error counter\n");
        }

        (void)fprintf(stderr, "error %lu bytes %lu packets\n", counter->bytes,
                      counter->packets);
    }

    // Loop over rules
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        (void)fprintf(stderr, "\trule: %d\n", rule->index);
        // Matchers
        (void)fprintf(stderr, "\t\tmatcher(s):\n");
        bf_list_foreach (&rule->matchers, matcher_node) {
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
            (void)fprintf(stderr, "\t\t\t\%s",
                          bf_matcher_type_to_str(matcher->type));
            (void)fprintf(stderr, " %s ", bf_matcher_op_to_str(matcher->op));

            bf_dump_hex_local(matcher->payload,
                              matcher->len - sizeof(struct bf_matcher));
            (void)fprintf(stderr, "\n");
        }

        // Print the counters and remove the head
        if (with_counters && rule->counters) {
            struct bf_list_node *head = bf_list_get_head(counters);
            if (!head) {
                return bf_err_r(-ENOENT, "no entry in list \n");
            }

            counter = (struct bf_counter *)bf_list_node_get_data(head);
            if (!counter) {
                return bf_err_r(-ENOENT, "got null error counter\n");
            }

            (void)fprintf(stderr, "\t\tcounters: %lu bytes %lu packets\n",
                          counter->bytes, counter->packets);
            bf_list_delete(counters, head);
        }

        (void)fprintf(stderr, "\t\tverdict: %s\n",
                      bf_verdict_to_str(rule->verdict));
    }

    if (with_counters) {
        // remove the chain counters: policy and error
        bf_list_delete(counters, bf_list_get_head(counters));
        bf_list_delete(counters, bf_list_get_head(counters));
    }

    (void)fprintf(stderr, "\n");

    return 0;
}

int bf_cli_dump_ruleset(bf_list *chains, bf_list *counters, bool with_counters)
{
    int r;

    bf_assert(chains);
    bf_assert(!with_counters || counters);

    // loop over all chains and print them
    bf_list_foreach (chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);

        r = bf_cli_chain_dump(chain, counters, with_counters);
        if (r < 0)
            return bf_err_r(r, "failed to dump chain");
    }

    return 0;
}
