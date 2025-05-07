
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/ruleset.h"

#include <argp.h>

#include "bfcli/helper.h"
#include "bfcli/print.h"
#include "core/chain.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"

void bfc_ruleset_clean(struct bfc_ruleset *ruleset)
{
    bf_assert(ruleset);

    bf_list_clean(&ruleset->chains);
    bf_list_clean(&ruleset->hookopts);
    bf_list_clean(&ruleset->sets);
}

struct bfc_ruleset_set_opts
{
    const char *input_file;
    const char *input_string;
};

struct bfc_ruleset_get_opts
{
    bool with_counters;
};

static error_t _bf_ruleset_set_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    struct bfc_ruleset_set_opts *opts = state->input;

    switch (key) {
    case 'f':
        opts->input_file = arg;
        break;
    case 's':
        opts->input_string = arg;
        break;
    case ARGP_KEY_END:
        if (!opts->input_file && !opts->input_string)
            return bf_err_r(-EINVAL,
                            "--from-file or --from-str argument is required");
        if (opts->input_file && opts->input_string)
            return bf_err_r(-EINVAL,
                            "--from-file is incompatible with --from-str");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int bfc_ruleset_set(int argc, char *argv[])
{
    static struct bfc_ruleset_set_opts opts = {
        .input_file = NULL,
    };
    static struct argp_option options[] = {
        {"from-file", 'f', "INPUT_FILE", 0, "Input file to use a rules source",
         0},
        {"from-str", 's', "INPUT_STRING", 0, "String to use as rules", 0},
        {0},
    };
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_set_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    struct bfc_ruleset ruleset = {
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),
        .sets = bf_set_list(),
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r) {
        bf_err_r(r, "failed to parse arguments");
        goto end_clean;
    }

    if (opts.input_file)
        r = bfc_parse_file(opts.input_file, &ruleset);
    else
        r = bfc_parse_str(opts.input_string, &ruleset);
    if (r) {
        bf_err_r(r, "failed to parse ruleset");
        goto end_clean;
    }

    // Send the chains to the daemon
    r = bf_cli_ruleset_set(&ruleset.chains, &ruleset.hookopts);
    if (r)
        bf_err_r(r, "failed to set ruleset");

end_clean:
    bf_list_clean(&ruleset.chains);
    bf_list_clean(&ruleset.sets);
    bf_list_clean(&ruleset.hookopts);

    return r;
}

static error_t _bf_ruleset_get_opts_parser(int key, const char *arg,
                                           struct argp_state *state)
{
    UNUSED(key);
    UNUSED(arg);
    UNUSED(state);

    return ARGP_ERR_UNKNOWN;
}

int bfc_ruleset_get(int argc, char *argv[])
{
    static struct argp_option options[] = {};
    struct argp argp = {
        options, (argp_parser_t)_bf_ruleset_get_opts_parser,
        NULL,    NULL,
        0,       NULL,
        NULL,
    };
    _clean_bf_list_ bf_list chains = bf_list_default(bf_chain_free, NULL);
    _clean_bf_list_ bf_list hookopts = bf_list_default(bf_hookopts_free, NULL);
    _clean_bf_list_ bf_list counters = bf_list_default(bf_list_free, NULL);
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, NULL);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    r = bf_cli_ruleset_get(&chains, &hookopts, &counters);
    if (r < 0)
        return bf_err_r(r, "failed to request ruleset");

    r = bfc_ruleset_dump(&chains, &hookopts, &counters);
    if (r)
        return bf_err_r(r, "failed to dump ruleset");

    return 0;
}
