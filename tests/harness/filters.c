/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "filters.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/chain.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/list.h"
#include "bpfilter/logger.h"
#include "bpfilter/matcher.h"
#include "bpfilter/rule.h"
#include "bpfilter/set.h"
#include "bpfilter/verdict.h"

struct bf_hookopts *bft_hookopts_get(const char *raw_opt, ...)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _clean_bf_list_ bf_list raw_options = bf_list_default(freep, NULL);
    va_list args;
    int r;

    va_start(args, raw_opt);
    do {
        _cleanup_free_ char *copy = strdup(raw_opt);
        if (!copy) {
            bf_err("failed to copy test hook option '%s'", raw_opt);
            va_end(args);
            return NULL;
        }

        r = bf_list_add_tail(&raw_options, copy);
        if (r) {
            bf_err("failed to insert raw option '%s' in list", raw_opt);
            va_end(args);
            return NULL;
        }

        TAKE_PTR(copy);
    } while ((raw_opt = va_arg(args, const char *)));
    va_end(args);

    r = bf_hookopts_new(&hookopts);
    if (r) {
        bf_err("failed to create a new bf_hookopts object");
        return NULL;
    }

    r = bf_hookopts_parse_opts(hookopts, &raw_options);
    if (r) {
        bf_err("failed to parse test hook options");
        return NULL;
    }

    return TAKE_PTR(hookopts);
}

struct bf_set *bft_set_get(enum bf_matcher_type *key, size_t n_comps,
                           void *data, size_t n_elems)
{
    _free_bf_set_ struct bf_set *set = NULL;
    int r;

    r = bf_set_new(&set, NULL, key, n_comps);
    if (r < 0) {
        bf_err_r(r, "failed to create a new test set");
        return NULL;
    }

    for (size_t i = 0; i < n_elems; ++i) {
        r = bf_set_add_elem(set, data + (i * set->elem_size));
        if (r < 0) {
            bf_err_r(r, "failed to add a new element to a test set");
            return NULL;
        }
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

struct bf_rule *bf_rule_get(uint8_t log, bool counters, enum bf_verdict verdict,
                            struct bf_matcher **matchers)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;
    int r;

    r = bf_rule_new(&rule);
    if (r < 0) {
        bf_err_r(r, "failed to create a new rule");
        goto err_free_matchers;
    }

    rule->log = log;
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
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list sets_list =
        bf_list_default(bf_set_free, bf_set_pack);
    _clean_bf_list_ bf_list rules_list =
        bf_list_default(bf_rule_free, bf_rule_pack);
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

    r = bf_chain_new(&chain, "bf_test", hook, policy, &sets_list, &rules_list);
    if (r < 0) {
        bf_err_r(r, "failed to create a new chain");
        return NULL;
    }

    return TAKE_PTR(chain);

err_free_arrays:
    while (sets && *sets)
        bf_set_free(sets++);
    while (rules && *rules)
        bf_rule_free(rules++);

    return NULL;
}

int bft_list_dummy_data_new_from_pack(struct bft_list_dummy_data **data,
                                      bf_rpack_node_t node)
{
    _cleanup_free_ struct bft_list_dummy_data *_data = NULL;
    size_t id;
    size_t len;
    const void *padding;
    size_t padding_len;
    int r;

    r = bf_rpack_kv_u64(node, "id", &id);
    if (r)
        return bf_rpack_key_err(r, "bft_list_dummy_data.id");

    r = bf_rpack_kv_u64(node, "len", &len);
    if (r)
        return bf_rpack_key_err(r, "bft_list_dummy_data.len");

    r = bf_rpack_kv_bin(node, "padding", &padding, &padding_len);
    if (r)
        return bf_rpack_key_err(r, "bft_list_dummy_data.padding");

    if (len != (sizeof(struct bft_list_dummy_data) + padding_len)) {
        return bf_err_r(-EINVAL,
                        "invalid serialized length for bft_list_dummy_data");
    }

    _data = malloc(len);
    if (!_data) {
        return bf_err_r(-ENOMEM,
                        "failed to allocate a bft_list_dummy_data object");
    }

    _data->id = id;
    _data->len = len;
    memcpy(_data->padding, padding, padding_len);

    *data = TAKE_PTR(_data);

    return 0;
}

int bft_list_dummy_data_pack(struct bft_list_dummy_data *data, bf_wpack_t *pack)
{
    bf_wpack_kv_u64(pack, "id", data->id);
    bf_wpack_kv_u64(pack, "len", data->len);
    bf_wpack_kv_bin(pack, "padding", data->padding, data->len - sizeof(*data));

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

bool bft_list_dummy_data_compare(const struct bft_list_dummy_data *lhs,
                                 const struct bft_list_dummy_data *rhs)
{
    return lhs->id == rhs->id && lhs->len == rhs->len &&
           0 == memcmp(lhs->padding, rhs->padding, lhs->len - sizeof(*lhs));
}

bf_list *bft_list_get(size_t n_elems, size_t elem_size)
{
    _free_bf_list_ bf_list *list = NULL;
    bf_list_ops ops = bf_list_ops_default(freep, bft_list_dummy_data_pack);
    int r;

    if (elem_size < sizeof(struct bft_list_dummy_data)) {
        elem_size = sizeof(struct bft_list_dummy_data);
        bf_warn("dummy bf_list element size if too small, using %lu",
                elem_size);
    }

    r = bf_list_new(&list, &ops);
    if (r) {
        bf_err("failed to create a dummy bf_list object");
        return NULL;
    }

    for (size_t i = 0; i < n_elems; ++i) {
        _cleanup_free_ struct bft_list_dummy_data *elem = NULL;

        elem = malloc(elem_size);
        if (!elem) {
            bf_err("failed to allocate a element for dummy bf_list object");
            return NULL;
        }

        elem->id = i;
        elem->len = elem_size;

        r = bf_list_add_tail(list, elem);
        if (r) {
            bf_err("failed to insert element into dummy bf_list object");
            return NULL;
        }

        TAKE_PTR(elem);
    }

    return TAKE_PTR(list);
}

bool bft_list_eq(const bf_list *lhs, const bf_list *rhs, bft_list_eq_cb cb)
{
    if (bf_list_size(lhs) != bf_list_size(rhs))
        return false;

    for (const bf_list_node *lhs_node = bf_list_get_head(lhs),
                            *rhs_node = bf_list_get_head(rhs);
         lhs_node && rhs_node; lhs_node = bf_list_node_next(lhs_node),
                            rhs_node = bf_list_node_next(rhs_node)) {
        if (!cb(bf_list_node_get_data(lhs_node),
                bf_list_node_get_data(rhs_node)))
            return false;
    }

    return true;
}
