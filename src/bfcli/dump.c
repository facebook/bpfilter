/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "dump.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"

// Declare all static functions here
static void bf_dump_hex_local(const void *data, size_t len);
static void bf_cli_chain_dump(struct bf_chain *chain, bool with_counters,
                              struct bf_counter **counter);

// TODO: Obviously resolve this duplication of bf_dump_hex
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
 * @param with_counters Boolean flag indicating whether to include counters in the dump.
 * @param counter Pointer to the array of counters associated with the chain. Must be non-NULL if with_counters is true.
 */
// TODO: Sort out our use of fprintf vs DUMP
// NOLINTBEGIN
static void bf_cli_chain_dump(struct bf_chain *chain, bool with_counters,
                              struct bf_counter **counter)
{
    bf_assert(chain);
    bf_assert(!with_counters || counter);

    struct bf_hook_opts *opts = &chain->hook_opts;

    fprintf(stderr, "chain %s", bf_hook_to_str(chain->hook));
    fprintf(stderr, "{");

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

    // So we can use bf_dump_hex_local
    bf_opts_set_verbose(BF_VERBOSE_DEBUG);

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

            bf_dump_hex_local(matcher->payload,
                              matcher->len - sizeof(struct bf_matcher));
            fprintf(stderr, "\n");
        }

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

int bf_cli_dump_ruleset(struct bf_marsh *chains_and_counters_marsh,
                        bool with_counters)
{
    struct bf_marsh *chains_marsh, *chain_marsh = NULL, *counters_marsh;
    struct bf_counter *counters;
    int r;

    bf_assert(chains_and_counters_marsh);

    // Get the chain list
    chains_marsh = bf_marsh_next_child(chains_and_counters_marsh, NULL);
    if (!chains_marsh) {
        bf_err("failed to locate chain list from daemon response\n");
        return -EINVAL;
    }

    // Get the array of counters
    counters_marsh =
        bf_marsh_next_child(chains_and_counters_marsh, chains_marsh);
    if (!counters_marsh) {
        bf_err("failed to locate counter array from daemon response\n");
        return -EINVAL;
    }

    counters = (struct bf_counter *)counters_marsh->data;

    // Loop over the chains
    while (true) {
        _cleanup_bf_chain_ struct bf_chain *chain = NULL;

        // Get the next child
        chain_marsh = bf_marsh_next_child(chains_marsh, chain_marsh);
        if (!chain_marsh) {
            break;
        }

        r = bf_chain_new_from_marsh(&chain, chain_marsh);
        if (r < 0)
            return bf_err_r(r, "failed to unmarsh chain");

        bf_cli_chain_dump(chain, with_counters, &counters);
    }

    return 0;
}
