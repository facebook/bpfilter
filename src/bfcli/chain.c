
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/chain.h"

#include <argp.h>
#include <errno.h>
#include <stdlib.h>

#include "bfcli/helper.h"
#include "bfcli/print.h"
#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"

struct bfc_chain_opts;

#define bf_ruleset_default()                                                   \
    {                                                                          \
        .chains = bf_list_default(bf_chain_free, bf_chain_marsh),              \
        .sets = bf_list_default(bf_set_free, bf_set_marsh),                    \
        .hookopts = bf_list_default(bf_hookopts_free, bf_hookopts_marsh),      \
    }

typedef int (*bfc_chain_opts_validation_cb_t)(struct bfc_chain_opts *opts,
                                              struct argp_state *state);

#define BFC_CHAIN_OPT_NAME {"name", 'n', "NAME", 0, "Name of the chain", 0}
#define BFC_CHAIN_OPT_FROM_STR                                                 \
    {"from-str", 's', "CHAIN", 0, "Chain(s) to use", 0}
#define BFC_CHAIN_OPT_FROM_FILE                                                \
    {"from-file", 'f', "FILE", 0, "File containing the chain(s) to use", 0}
#define BFC_CHAIN_OPT_HOOKOPT                                                  \
    {"option", 'o', "HOOKOPT=VALUE", 0, "Hook option to attach the chain", 0}

struct bfc_chain_opts
{
    const char *name;
    const char *from_str;
    const char *from_file;
    struct bf_hookopts *hookopts;
    bfc_chain_opts_validation_cb_t validation_cb;
};

extern char *program_invocation_name;

static error_t _bfc_chain_opts_parser(int key, const char *arg,
                                      struct argp_state *state)
{
    struct bfc_chain_opts *opts = state->input;
    int r = 0;

    switch (key) {
    case 'n':
        opts->name = arg;
        break;
    case 's':
        opts->from_str = arg;
        break;
    case 'f':
        opts->from_file = arg;
        break;
    case 'o':
        r = bf_hookopts_parse_opt(opts->hookopts, arg);
        if (r)
            bf_err_r(r, "failed to parse hook option '%s'", arg);
        break;
    case ARGP_KEY_END:
        if (opts->validation_cb)
            r = opts->validation_cb(opts, state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return r;
}

static int _bfc_get_chain_from_ruleset(const struct bf_ruleset *ruleset,
                                       const char *name,
                                       struct bf_chain **chain,
                                       struct bf_hookopts **hookopts)
{
    struct bf_chain *_chain = NULL;
    struct bf_hookopts *_hookopts = NULL;

    if (bf_list_is_empty(&ruleset->chains))
        return bf_err_r(-ENOENT, "no chain define in source");

    if (!name && bf_list_size(&ruleset->chains) > 1) {
        return bf_err_r(
            -E2BIG, "multiple chains defined in source, but no name specified");
    }

    if (!name && bf_list_size(&ruleset->chains) == 1) {
        _chain = bf_list_node_get_data(bf_list_get_head(&ruleset->chains));
        _hookopts = bf_list_node_get_data(bf_list_get_head(&ruleset->hookopts));
    } else {
        // Name is defined, and we have at least 1 chain in the list
        for (struct bf_list_node *
                 chain_node = bf_list_get_head(&ruleset->chains),
                *hookopts_node = bf_list_get_head(&ruleset->hookopts);
             chain_node && hookopts_node;
             chain_node = bf_list_node_next(chain_node),
                hookopts_node = bf_list_node_next(hookopts_node)) {
            struct bf_chain *chain_tmp = bf_list_node_get_data(chain_node);

            if (bf_streq(chain_tmp->name, name)) {
                _chain = chain_tmp;
                _hookopts = bf_list_node_get_data(hookopts_node);
                break;
            }
        }
    }

    if (_chain)
        *chain = _chain;
    else
        return bf_err_r(-ENOENT, "chain '%s' not found", name);

    if (_hookopts)
        *hookopts = _hookopts;

    return 0;
}

static int _bfc_chain_set_validate_cb(struct bfc_chain_opts *opts,
                                      struct argp_state *state)
{
    if (opts->from_str && opts->from_file) {
        argp_error(state, "--from-str is incompatible with --from-file");
        return -EINVAL;
    }

    if (!opts->from_str && !opts->from_file) {
        argp_error(state, "either --from-str or --from-file is required");
        return -EINVAL;
    }

    return 0;
}

int bfc_chain_set(int argc, char **argv)
{
    static struct argp_option options[] = {
        BFC_CHAIN_OPT_NAME,
        BFC_CHAIN_OPT_FROM_STR,
        BFC_CHAIN_OPT_FROM_FILE,
        {0},
    };

    struct bf_chain *chain = NULL;
    struct bf_hookopts *hookopts = NULL;
    _clean_bf_ruleset_ struct bf_ruleset ruleset = bf_ruleset_default();
    struct bfc_chain_opts opts = {
        .validation_cb = _bfc_chain_set_validate_cb,
    };
    struct argp argp = {
        options, (argp_parser_t)_bfc_chain_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    bf_info("chain: '%s'", opts.from_str);
    if (opts.from_str)
        r = bfc_parse_str(opts.from_str, &ruleset);
    else
        r = bfc_parse_file(opts.from_file, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse the chain(s)");

    r = _bfc_get_chain_from_ruleset(&ruleset, opts.name, &chain, &hookopts);
    if (r)
        return r;

    r = bf_chain_set(chain, hookopts);
    if (r)
        return bf_err_r(r, "unknown error");

    return 0;
}

static int _bfc_chain_get_validate_cb(struct bfc_chain_opts *opts,
                                      struct argp_state *state)
{
    if (!opts->name) {
        argp_error(state, "the --name (-n) parameter is required");
        return -ENOENT;
    }

    return 0;
}

int bfc_chain_get(int argc, char **argv)
{
    static struct argp_option options[] = {
        BFC_CHAIN_OPT_NAME,
        {0},
    };

    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _clean_bf_list_ bf_list counters = bf_list_default(bf_counter_free, NULL);
    struct bfc_chain_opts opts = {
        .validation_cb = _bfc_chain_get_validate_cb,
    };
    struct argp argp = {
        options, (argp_parser_t)_bfc_chain_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    r = bf_chain_get(opts.name, &chain, &hookopts, &counters);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts.name);
    if (r)
        return bf_err_r(r, "unknown error");

    bfc_chain_dump(chain, hookopts, &counters);

    return 0;
}

static int _bfc_chain_load_validate_cb(struct bfc_chain_opts *opts,
                                       struct argp_state *state)
{
    if (opts->from_str && opts->from_file) {
        argp_error(state, "--from-str is incompatible with --from-file");
        return -EINVAL;
    }

    if (!opts->from_str && !opts->from_file) {
        argp_error(state, "either --from-str or --from-file is required");
        return -EINVAL;
    }

    return 0;
}

int bfc_chain_load(int argc, char **argv)
{
    static struct argp_option options[] = {
        BFC_CHAIN_OPT_FROM_STR,
        BFC_CHAIN_OPT_FROM_FILE,
        BFC_CHAIN_OPT_NAME,
        {0},
    };

    struct bf_chain *chain = NULL;
    struct bf_hookopts *hookopts = NULL;
    _clean_bf_ruleset_ struct bf_ruleset ruleset = bf_ruleset_default();
    struct bfc_chain_opts opts = {
        .validation_cb = _bfc_chain_load_validate_cb,
    };
    struct argp argp = {
        options, (argp_parser_t)_bfc_chain_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    if (opts.from_str)
        r = bfc_parse_str(opts.from_str, &ruleset);
    else
        r = bfc_parse_file(opts.from_file, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse the chain(s)");

    r = _bfc_get_chain_from_ruleset(&ruleset, opts.name, &chain, &hookopts);
    if (r)
        return r;

    if (hookopts)
        bf_warn("Hook options are ignored when loading a chain");

    r = bf_chain_load(chain);
    if (r)
        return bf_err_r(r, "unknown error");

    return 0;
}

static int _bfc_chain_attach_validate_cb(struct bfc_chain_opts *opts,
                                         struct argp_state *state)
{
    if (!opts->name) {
        argp_error(state, "--name is required");
        return -EINVAL;
    }

    return 0;
}

int bfc_chain_attach(int argc, char **argv)
{
    static struct argp_option options[] = {
        BFC_CHAIN_OPT_NAME,
        BFC_CHAIN_OPT_HOOKOPT,
        {0},
    };

    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    struct bfc_chain_opts opts = {
        .validation_cb = _bfc_chain_attach_validate_cb,
    };
    struct argp argp = {
        options, (argp_parser_t)_bfc_chain_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    int r;

    r = bf_hookopts_new(&hookopts);
    if (r)
        return r;

    opts.hookopts = hookopts;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    r = bf_chain_attach(opts.name, opts.hookopts);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts.name);
    if (r)
        return bf_err_r(r, "unknown error");

    return r;
}

static int _bfc_chain_update_validate_cb(struct bfc_chain_opts *opts,
                                         struct argp_state *state)
{
    if (opts->from_str && opts->from_file) {
        argp_error(state, "--from-str is incompatible with --from-file");
        return -EINVAL;
    }

    if (!opts->from_str && !opts->from_file) {
        argp_error(state, "either --from-str or --from-file is required");
        return -EINVAL;
    }

    return 0;
}

int bfc_chain_update(int argc, char **argv)
{
    static struct argp_option options[] = {
        BFC_CHAIN_OPT_FROM_STR,
        BFC_CHAIN_OPT_FROM_FILE,
        BFC_CHAIN_OPT_NAME,
        {0},
    };

    struct bf_chain *chain = NULL;
    struct bf_hookopts *hookopts = NULL;
    _clean_bf_ruleset_ struct bf_ruleset ruleset = bf_ruleset_default();
    struct bfc_chain_opts opts = {
        .validation_cb = _bfc_chain_update_validate_cb,
    };
    struct argp argp = {
        options, (argp_parser_t)_bfc_chain_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    if (opts.from_str)
        r = bfc_parse_str(opts.from_str, &ruleset);
    else
        r = bfc_parse_file(opts.from_file, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse the chain(s)");

    r = _bfc_get_chain_from_ruleset(&ruleset, opts.name, &chain, &hookopts);
    if (r)
        return r;

    if (hookopts)
        bf_warn("Hook options are ignored when updating a chain");

    r = bf_chain_update(chain);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts.name);
    if (r == -ENOLINK)
        return bf_err_r(r, "chain '%s' is not attached to a hook", opts.name);
    if (r)
        return bf_err_r(r, "unknown error");

    return r;
}

static int _bfc_chain_flush_validate_cb(struct bfc_chain_opts *opts,
                                        struct argp_state *state)
{
    if (!opts->name) {
        argp_error(state, "the --name (-n) parameter is required");
        return -ENOENT;
    }

    return 0;
}

int bfc_chain_flush(int argc, char **argv)
{
    static struct argp_option options[] = {
        BFC_CHAIN_OPT_NAME,
        {0},
    };

    struct bfc_chain_opts opts = {
        .validation_cb = _bfc_chain_flush_validate_cb,
    };
    struct argp argp = {
        options, (argp_parser_t)_bfc_chain_opts_parser, NULL, NULL, 0, NULL,
        NULL,
    };
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return bf_err_r(r, "failed to parse arguments");

    r = bf_chain_flush(opts.name);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts.name);
    if (r)
        return bf_err_r(r, "unknown error");

    return r;
}
