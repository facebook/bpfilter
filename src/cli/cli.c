/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "cli/lexer.h"
#include "cli/parser.h"
#include "core/chain.h"
#include "core/dump.h"
#include "core/list.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/set.h"

int bf_send(const struct bf_request *request, struct bf_response **response);

static struct bf_options
{
    const char *input_file;
} _opts = {
    .input_file = NULL,
};

static struct argp_option options[] = {
    {"file", 'f', "INPUT_FILE", 0, "Input file to use a rules source", 0},
    {0},
};

static error_t _bf_opts_parser(int key, char *arg, struct argp_state *state)
{
    UNUSED(arg);

    struct bf_options *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = strdup(arg);
        if (!opts->input_file) {
            fprintf(stderr, "failed to allocate memory for '%s'\n", arg);
            return -ENOMEM;
        }
        break;
    case ARGP_KEY_END:
        if (!opts->input_file) {
            fprintf(stderr, "--file is required\n");
            return -EINVAL;
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct argp argp = {options, _bf_opts_parser, NULL, NULL, 0, NULL, NULL};
    bf_list chains = bf_list_default({.free = (bf_list_ops_free)bf_chain_free});
    bf_list sets = bf_list_default({.free = (bf_list_ops_free)bf_set_free});
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &_opts);
    if (r) {
        fprintf(stderr, "failed to parse arguments\n");
        return EXIT_FAILURE;
    }

    printf("Using source file: %s\n", _opts.input_file);

    FILE *rules = fopen(_opts.input_file, "r");
    if (!rules) {
        fprintf(stderr, "Failed to read rules from 'rule.bpfilter'\n");
        return -1;
    }

    yyin = rules;

    r = yyparse(&chains, &sets);
    if (r == 1) {
        fprintf(stderr, "failed to parse rules, syntax invalid\n");
        return EXIT_FAILURE;
    } else if (r == 2) {
        fprintf(stderr, "failed to parse rules, not enough memory\n");
        return EXIT_FAILURE;
    }

    // Set rules indexes
    bf_list_foreach (&chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        uint32_t index = 0;

        bf_list_foreach (&chain->rules, rule_node) {
            struct bf_rule *rule = bf_list_node_get_data(rule_node);
            rule->index = index++;
        }
    }

    bf_list_foreach (&chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        _cleanup_bf_request_ struct bf_request *request = NULL;
        _cleanup_bf_response_ struct bf_response *response = NULL;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        r = bf_chain_marsh(chain, &marsh);
        if (r) {
            fprintf(stderr, "failed to marsh chain, skipping\n");
            continue;
        }

        r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
        if (r) {
            fprintf(stderr, "failed to create request for chain, skipping\n");
            continue;
        }

        request->front = BF_FRONT_CLI;
        request->cmd = BF_REQ_SET_RULES;

        r = bf_send(request, &response);
        if (r) {
            fprintf(stderr,
                    "failed to send chain creation request, skipping\n");
            continue;
        }

        if (response->type == BF_RES_FAILURE) {
            fprintf(stderr, "chain creation request failed, %d received\n",
                    response->error);
            continue;
        }
    }

    bf_list_clean(&chains);
    fclose(rules);

    return 0;
}

void yyerror(bf_list *chains, bf_list *sets, const char *fmt, ...)
{
    UNUSED(chains);
    UNUSED(sets);

    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(-1);
}
