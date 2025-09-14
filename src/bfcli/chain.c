
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "chain.h"

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>

#include "helper.h"
#include "opts.h"
#include "print.h"
#include "ruleset.h"

#define BF_RB_POLL_TIMEOUT 1000

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
    _free_bf_chain_ struct bf_chain *chain = NULL;
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

static int _bf_handle_rb_log(void *ctx, void *data, size_t data_size)
{
    struct bf_log *log = data;

    UNUSED(ctx);
    UNUSED(data_size);

    bfc_print_log(log);

    return 0;
}

int bfc_chain_logs(const struct bfc_opts *opts)
{
    _cleanup_close_ int fd = -1;
    struct ring_buffer *rb;
    int r;

    fd = bf_chain_logs_fd(opts->name);
    if (fd < 0) {
        return bf_err_r(fd, "failed to request '%s' logs buffer FD",
                        opts->name);
    }

    rb = ring_buffer__new(fd, _bf_handle_rb_log, NULL, NULL);
    if (!rb)
        return bf_err_r(-EINVAL, "failed to create libbpf ring buffer");

    while (1) {
        r = ring_buffer__poll(rb, BF_RB_POLL_TIMEOUT);
        if (r == -EINTR)
            continue;

        if (r < 0) {
            r = bf_err_r(r, "failed to poll ring buffer");
            break;
        }
    }

    ring_buffer__free(rb);

    return r;
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
