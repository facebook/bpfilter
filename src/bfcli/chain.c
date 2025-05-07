
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/chain.h"

#include <argp.h>
#include <errno.h>
#include <stdlib.h>

#include "bfcli/helper.h"
#include "bfcli/opts.h"
#include "bfcli/print.h"
#include "bfcli/ruleset.h"
#include "core/chain.h"
#include "core/counter.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"

struct bfc_chain_opts;

static int _bfc_get_chain_from_ruleset(const struct bfc_ruleset *ruleset,
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

int bfc_chain_set(const struct bfc_opts *opts)
{
    struct bf_chain *chain = NULL;
    struct bf_hookopts *hookopts = NULL;
    _clean_bfc_ruleset_ struct bfc_ruleset ruleset = bfc_ruleset_default();
    int r;

    if (opts->from_str)
        r = bfc_parse_str(opts->from_str, &ruleset);
    else
        r = bfc_parse_file(opts->from_file, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse the chain(s)");

    r = _bfc_get_chain_from_ruleset(&ruleset, opts->name, &chain, &hookopts);
    if (r)
        return r;

    r = bf_chain_set(chain, hookopts);
    if (r)
        return bf_err_r(r, "unknown error");

    return 0;
}

int bfc_chain_get(const struct bfc_opts *opts)
{
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _clean_bf_list_ bf_list counters = bf_list_default(bf_counter_free, NULL);
    int r;

    r = bf_chain_get(opts->name, &chain, &hookopts, &counters);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts->name);
    if (r)
        return bf_err_r(r, "unknown error");

    bfc_chain_dump(chain, hookopts, &counters);

    return 0;
}

int bfc_chain_load(const struct bfc_opts *opts)
{
    struct bf_chain *chain = NULL;
    struct bf_hookopts *hookopts = NULL;
    _clean_bfc_ruleset_ struct bfc_ruleset ruleset = bfc_ruleset_default();
    int r;

    if (opts->from_str)
        r = bfc_parse_str(opts->from_str, &ruleset);
    else
        r = bfc_parse_file(opts->from_file, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse the chain(s)");

    r = _bfc_get_chain_from_ruleset(&ruleset, opts->name, &chain, &hookopts);
    if (r)
        return r;

    if (hookopts)
        bf_warn("Hook options are ignored when loading a chain");

    r = bf_chain_load(chain);
    if (r)
        return bf_err_r(r, "unknown error");

    return 0;
}

int bfc_chain_attach(const struct bfc_opts *opts)
{
    int r;

    r = bf_chain_attach(opts->name, &opts->hookopts);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts->name);
    if (r)
        return bf_err_r(r, "unknown error");

    return r;
}

int bfc_chain_update(const struct bfc_opts *opts)
{
    struct bf_chain *chain = NULL;
    struct bf_hookopts *hookopts = NULL;
    _clean_bfc_ruleset_ struct bfc_ruleset ruleset = bfc_ruleset_default();
    int r;

    if (opts->from_str)
        r = bfc_parse_str(opts->from_str, &ruleset);
    else
        r = bfc_parse_file(opts->from_file, &ruleset);
    if (r)
        return bf_err_r(r, "failed to parse the chain(s)");

    r = _bfc_get_chain_from_ruleset(&ruleset, opts->name, &chain, &hookopts);
    if (r)
        return r;

    if (hookopts)
        bf_warn("Hook options are ignored when updating a chain");

    r = bf_chain_update(chain);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts->name);
    if (r == -ENOLINK)
        return bf_err_r(r, "chain '%s' is not attached to a hook", opts->name);
    if (r)
        return bf_err_r(r, "unknown error");

    return r;
}

int bfc_chain_flush(const struct bfc_opts *opts)
{
    int r;

    r = bf_chain_flush(opts->name);
    if (r == -ENOENT)
        return bf_err_r(r, "chain '%s' not found", opts->name);
    if (r)
        return bf_err_r(r, "unknown error");

    return r;
}
