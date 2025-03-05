/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/filters.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/chain.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/matcher.h"
#include "core/rule.h"
#include "core/set.h"
#include "core/verdict.h"

struct bf_hook_opts bf_hook_opts_get(enum bf_hook_opt opt, ...)
{
    struct bf_hook_opts opts = {};
    va_list args;

    va_start(args, opt);
    do {
        switch (opt) {
        case BF_HOOK_OPT_IFINDEX:
            opts.ifindex = va_arg(args, uint32_t);
            break;
        case BF_HOOK_OPT_CGROUP:
            opts.cgroup = strdup(va_arg(args, char *));
            if (!opts.cgroup) {
                bf_err("failed to copy 'cgroup' hook option, aborting");
                goto err_clean;
            }
            break;
        case BF_HOOK_OPT_NAME:
            opts.name = strdup(va_arg(args, char *));
            if (!opts.name) {
                bf_err("failed to copy 'name' hook option, aborting");
                goto err_clean;
            }
            break;
        case BF_HOOK_OPT_ATTACH:
            opts.attach = va_arg(args, int);
            break;
        default:
            bf_err("unknown hook option %d, aborting", opt);
            goto err_clean;
        }

        opts.used_opts |= 1 << opt;
    } while ((int)(opt = va_arg(args, enum bf_hook_opt)) != -1);
    va_end(args);

    return opts;

err_clean:
    va_end(args);
    bf_hook_opts_clean(&opts);

    return (struct bf_hook_opts) {};
}

struct bf_set *bf_test_set_get(enum bf_set_type type, uint8_t *data[])
{
    _cleanup_bf_set_ struct bf_set *set = NULL;
    int r;

    r = bf_set_new(&set, type);
    if (r < 0) {
        bf_err_r(r, "failed to create a new test set");
        return NULL;
    }

    while (data && *data) {
        r = bf_set_add_elem(set, *data);
        if (r < 0) {
            bf_err_r(r, "failed to add a new element to a test set");
            return NULL;
        }
        ++data;
    }

    return TAKE_PTR(set);
}

struct bf_matcher *bf_matcher_get(enum bf_matcher_type type,
                                  enum bf_matcher_op op, const void *payload,
                                  size_t payload_len)
{
    struct bf_matcher *matcher = NULL;
    int r;

    r = bf_matcher_new(&matcher, type, op, payload, payload_len);
    if (r < 0) {
        bf_err_r(r, "failed to create a new matcher");
        return NULL;
    }

    return matcher;
}

struct bf_rule *bf_rule_get(bool counters, enum bf_verdict verdict,
                            struct bf_matcher **matchers)
{
    _cleanup_bf_rule_ struct bf_rule *rule = NULL;
    int r;

    r = bf_rule_new(&rule);
    if (r < 0) {
        bf_err_r(r, "failed to create a new rule");
        goto err_free_matchers;
    }

    rule->counters = counters;
    rule->verdict = verdict;

    while (*matchers) {
        r = bf_list_add_tail(&rule->matchers, *matchers);
        if (r < 0) {
            bf_err_r(r, "failed to add matcher to rule");
            goto err_free_matchers;
        }

        ++matchers;
    }

    return TAKE_PTR(rule);

err_free_matchers:
    while (*matchers)
        bf_matcher_free(matchers++);

    return NULL;
}

struct bf_chain *bf_test_chain_get(enum bf_hook hook, enum bf_verdict policy,
                                   struct bf_set **sets, struct bf_rule **rules)
{
    _cleanup_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list sets_list = bf_set_list();
    _clean_bf_list_ bf_list rules_list = bf_rule_list();
    int r;

    while (sets && *sets) {
        r = bf_list_add_tail(&sets_list, *sets);
        if (r < 0) {
            bf_err_r(r, "failed to add set to list");
            goto err_free_arrays;
        }

        ++sets;
    }

    while (rules && *rules) {
        r = bf_list_add_tail(&rules_list, *rules);
        if (r < 0) {
            bf_err_r(r, "failed to add rule to list");
            goto err_free_arrays;
        }

        ++rules;
    }

    r = bf_chain_new(&chain, hook, policy, &sets_list, &rules_list);
    if (r < 0) {
        bf_err_r(r, "failed to create a new chain");
        return NULL;
    }

    chain->hook_opts = (struct bf_hook_opts) {
        .used_opts = ~0U,
        .attach = false,
        .cgroup = strdup("<no_cgroup>"),
        .ifindex = 1,
        .name = strdup(BF_E2E_NAME),
    };

    return TAKE_PTR(chain);

err_free_arrays:
    while (sets && *sets)
        bf_set_free(sets++);
    while (rules && *rules)
        bf_rule_free(rules++);

    return NULL;
}
