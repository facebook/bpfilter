/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bfcli/lexer.h"
#include "bfcli/parser.h"
#include "core/chain.h"
#include "core/front.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/set.h"

int bf_send(const struct bf_request *request, struct bf_response **response);

static struct bf_options
{
    const char *input_file;
} _bf_opts = {
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
        if (!opts->input_file)
            return bf_err_r(-ENOMEM, "failed to copy input file path");
        break;
    case ARGP_KEY_END:
        if (!opts->input_file)
            return bf_err_r(-EINVAL, "--file argument is required");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct argp argp = {options, _bf_opts_parser, NULL, NULL, 0, NULL, NULL};
    struct bf_ruleset ruleset = {
        .chains = bf_list_default({.free = (bf_list_ops_free)bf_chain_free}),
        .sets = bf_list_default({.free = (bf_list_ops_free)bf_set_free}),
    };
    int r;

    bf_logger_setup();

    r = argp_parse(&argp, argc, argv, 0, 0, &_bf_opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    bf_info("using source file: %s", _bf_opts.input_file);

    FILE *rules = fopen(_bf_opts.input_file, "r");
    if (!rules) {
        r = errno;
        bf_err_r(r, "failed to read rules from %s:", _bf_opts.input_file);
        goto end_clean;
    }

    yyin = rules;

    r = yyparse(&ruleset);
    if (r == 1) {
        bf_err("failed to parse rules, invalid syntax");
        r = -EINVAL;
        goto end_close;
    } else if (r == 2) {
        bf_err("failed to parse rules, not enough memory");
        r = -EINVAL;
        goto end_close;
    }

    // Set rules indexes
    bf_list_foreach (&ruleset.chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        uint32_t index = 0;

        bf_list_foreach (&chain->rules, rule_node) {
            struct bf_rule *rule = bf_list_node_get_data(rule_node);
            rule->index = index++;
        }
    }

    bf_list_foreach (&ruleset.chains, chain_node) {
        struct bf_chain *chain = bf_list_node_get_data(chain_node);
        _cleanup_bf_request_ struct bf_request *request = NULL;
        _cleanup_bf_response_ struct bf_response *response = NULL;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        r = bf_chain_marsh(chain, &marsh);
        if (r) {
            bf_err_r(r, "failed to marsh chain, skipping");
            continue;
        }

        r = bf_request_new(&request, marsh, bf_marsh_size(marsh));
        if (r) {
            bf_err_r(r, "failed to create request for chain, skipping");
            continue;
        }

        request->front = BF_FRONT_CLI;
        request->cmd = BF_REQ_SET_RULES;

        r = bf_send(request, &response);
        if (r) {
            bf_err_r(r, "failed to send chain creation request, skipping");
            continue;
        }

        if (response->type == BF_RES_FAILURE) {
            bf_err_r(response->error, "chain creation request failed");
            continue;
        }
    }

end_close:
    (void)fclose(rules);
end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);

    return r;
}

void yyerror(struct bf_ruleset *ruleset, const char *fmt, ...)
{
    UNUSED(ruleset);

    va_list args;

    va_start(args, fmt);
    bf_err_v(fmt, args);
    va_end(args);
}
