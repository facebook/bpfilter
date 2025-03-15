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

#include "bfcli/dump.h"
#include "bfcli/lexer.h"
#include "bfcli/parser.h"
#include "core/chain.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/request.h"
#include "core/response.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"
#include "version.h"

int bf_send(const struct bf_request *request, struct bf_response **response);

struct bf_ruleset_set_opts
{
    const char *input_file;
    const char *input_string;
};

struct bf_ruleset_get_opts
{
    bool with_counters;
};

enum
{
    BF_OPT_COUNTERS = 1,
};

static error_t _bf_ruleset_set_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    struct bf_ruleset_set_opts *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = arg;
        break;
    case 's':
        opts->input_string = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->input_file && !opts->input_string)
            return bf_err_r(-EINVAL, "--file or --str argument is required");
        if (opts->input_file && opts->input_string)
            return bf_err_r(-EINVAL, "--file is incompatible with --str");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static error_t _bf_ruleset_get_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    struct bf_ruleset_get_opts *opts = state->input;
    UNUSED(arg);

    switch (key) {
    case BF_OPT_COUNTERS:
        opts->with_counters = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int _bf_cli_parse_file(const char *file, struct bf_ruleset *ruleset)
{
    FILE *rules;
    int r;

    rules = fopen(file, "r");
    if (!rules)
        return bf_err_r(errno, "failed to read rules from %s:", file);

    yyin = rules;

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    return r;
}

static int _bf_cli_parse_str(const char *str, struct bf_ruleset *ruleset)
{
    YY_BUFFER_STATE buffer;
    int r;

    buffer = yy_scan_string(str);

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    yy_delete_buffer(buffer);

    return r;
}

int _bf_do_ruleset_set(int argc, char *argv[])
{
    static struct bf_ruleset_set_opts opts = {
        .input_file = NULL,
    };
    static struct argp_option options[] = {
        {"file", 'f', "INPUT_FILE", 0, "Input file to use a rules source", 0},
        {"str", 's', "INPUT_STRING", 0, "String to use as rules", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_set_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    struct bf_ruleset ruleset = {
        .chains = bf_chain_list(),
        .sets = bf_set_list(),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    if (opts.input_file)
        r = _bf_cli_parse_file(opts.input_file, &ruleset);
    else
        r = _bf_cli_parse_str(opts.input_string, &ruleset);
    if (r) {
        bf_err_r(r, "failed to parse ruleset");
        goto end_clean;
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

    // Send the chains to the daemon
    bf_list_foreach (&ruleset.chains, chain_node) {
        const struct bf_chain *chain = bf_list_node_get_data(chain_node);

        r = bf_cli_set_chain(chain);
        if (r < 0) {
            bf_err("failed to set chain for '%s', skipping remaining chains",
                   bf_hook_to_str(chain->hook));
            goto end_clean;
        }
    }

end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);

    return r;
}

#define streq(str, expected) (str) && bf_streq(str, expected)

int _bf_do_ruleset_get(int argc, char *argv[])
{
    static struct bf_ruleset_get_opts opts = {
        .with_counters = false,
    };
    static struct argp_option options[] = {
        // use enum
        {"with-counters", BF_OPT_COUNTERS, 0, 0,
         "Print rule and chain counters", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_get_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        bf_err_r(r, "failed to parse arguments");

    // Ask libbpfilter to make a request to the daemon
    r = bf_cli_request_ruleset(&response, opts.with_counters);
    if (r < 0)
        return bf_err_r(r, "failed to request ruleset\n");

    if (response->type == BF_RES_FAILURE)
        return bf_err_r(response->error, "failed to get ruleset\n");

    if (response->data_len == 0) {
        bf_info("no ruleset returned\n");
        return 0;
    }

    r = bf_cli_dump_ruleset((struct bf_marsh *)response->data,
                            opts.with_counters);
    if (r)
        return bf_err_r(r, "failed to dump ruleset\n");

    return 0;
}

int main(int argc, char *argv[])
{
    const char *obj_str = NULL;
    const char *action_str = NULL;
    int argv_skip = 0;
    int r;

    if (argc > 1 && argv[1][0] != '-') {
        obj_str = argv[1];
        ++argv_skip;
    }

    if (obj_str && argc > 2 && argv[2][0] != '-') {
        action_str = argv[2];
        ++argv_skip;
    }

    argv += argv_skip;
    argc -= argv_skip;

    bf_logger_setup();

    // If any of the arguments is --version, print the version and return.
    for (int i = 0; i < argc; ++i) {
        if (bf_streq("--version", argv[i])) {
            bf_info("bfcli version %s, libbpfilter version %s", BF_VERSION,
                    bf_version());
            exit(0);
        }
    }

    if (streq(obj_str, "ruleset") && streq(action_str, "set")) {
        r = _bf_do_ruleset_set(argc, argv);
    } else if (streq(obj_str, "ruleset") && streq(action_str, "get")) {
        r = _bf_do_ruleset_get(argc, argv);
    } else if (streq(obj_str, "ruleset") && streq(action_str, "flush")) {
        r = bf_cli_ruleset_flush();
    } else {
        return bf_err_r(-EINVAL, "unrecognized object '%s' and action '%s'",
                        obj_str, action_str);
    }

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
