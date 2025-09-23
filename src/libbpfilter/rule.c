/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/rule.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/list.h"
#include "bpfilter/logger.h"
#include "bpfilter/matcher.h"
#include "bpfilter/pack.h"
#include "bpfilter/runtime.h"
#include "bpfilter/verdict.h"

static const char *_bf_pkthdr_strs[] = {
    [BF_PKTHDR_LINK] = "link",
    [BF_PKTHDR_INTERNET] = "internet",
    [BF_PKTHDR_TRANSPORT] = "transport",
};
static_assert_enum_mapping(_bf_pkthdr_strs, _BF_PKTHDR_MAX);

const char *bf_pkthdr_to_str(enum bf_pkthdr hdr)
{
    bf_assert(hdr < _BF_PKTHDR_MAX);

    return _bf_pkthdr_strs[hdr];
}

int bf_pkthdr_from_str(const char *str, enum bf_pkthdr *hdr)
{
    bf_assert(str);

    for (int i = 0; i < _BF_PKTHDR_MAX; ++i) {
        if (bf_streq_i(str, _bf_pkthdr_strs[i])) {
            *hdr = (enum bf_pkthdr)i;
            return 0;
        }
    }

    return -EINVAL;
}

int bf_rule_new(struct bf_rule **rule)
{
    struct bf_rule *_rule;

    bf_assert(rule);

    _rule = calloc(1, sizeof(*_rule));
    if (!_rule)
        return -ENOMEM;

    _rule->matchers = bf_list_default(bf_matcher_free, bf_matcher_pack);

    *rule = _rule;

    return 0;
}

int bf_rule_new_from_pack(struct bf_rule **rule, bf_rpack_node_t node)
{
    _free_bf_rule_ struct bf_rule *_rule = NULL;
    bf_rpack_node_t m_nodes, m_node;
    int r;

    bf_assert(rule);

    r = bf_rule_new(&_rule);
    if (r)
        return bf_err_r(r, "failed to create bf_rule from pack");

    r = bf_rpack_kv_u32(node, "index", &_rule->index);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.index");

    r = bf_rpack_kv_u8(node, "log", &_rule->log);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.log");

    r = bf_rpack_kv_bool(node, "counters", &_rule->counters);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.counters");

    r = bf_rpack_kv_u64(node, "mark", &_rule->mark);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.mark");

    r = bf_rpack_kv_enum(node, "verdict", &_rule->verdict);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.verdict");

    r = bf_rpack_kv_array(node, "matchers", &m_nodes);
    if (r)
        return bf_rpack_key_err(r, "bf_rule.matchers");
    bf_rpack_array_foreach (m_nodes, m_node) {
        _free_bf_matcher_ struct bf_matcher *matcher = NULL;

        r = bf_list_emplace(&_rule->matchers, bf_matcher_new_from_pack, matcher,
                            m_node);
        if (r) {
            return bf_err_r(
                r, "failed to unpack bf_matcher into bf_rule.matchers");
        }
    }

    *rule = TAKE_PTR(_rule);

    return 0;
}

void bf_rule_free(struct bf_rule **rule)
{
    bf_assert(rule);

    if (!*rule)
        return;

    bf_list_clean(&(*rule)->matchers);

    free(*rule);
    *rule = NULL;
}

int bf_rule_pack(const struct bf_rule *rule, bf_wpack_t *pack)
{
    bf_assert(rule);
    bf_assert(pack);

    bf_wpack_kv_u32(pack, "index", rule->index);
    bf_wpack_kv_u8(pack, "log", rule->log);
    bf_wpack_kv_bool(pack, "counters", rule->counters);
    bf_wpack_kv_u64(pack, "mark", rule->mark);
    bf_wpack_kv_int(pack, "verdict", rule->verdict);

    bf_wpack_kv_list(pack, "matchers", &rule->matchers);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_rule_dump(const struct bf_rule *rule, prefix_t *prefix)
{
    bf_assert(rule);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_rule at %p", rule);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "index: %u", rule->index);

    // Matchers
    DUMP(prefix, "matchers: %lu", bf_list_size(&rule->matchers));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

        if (bf_list_is_tail(&rule->matchers, matcher_node))
            bf_dump_prefix_last(prefix);

        bf_matcher_dump(matcher, prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(prefix, "log: %02x", rule->log);
    DUMP(prefix, "counters: %s", rule->counters ? "yes" : "no");
    DUMP(prefix, "mark: 0x%" PRIx64, rule->mark);
    DUMP(bf_dump_prefix_last(prefix), "verdict: %s",
         bf_verdict_to_str(rule->verdict));

    bf_dump_prefix_pop(prefix);
}

int bf_rule_add_matcher(struct bf_rule *rule, enum bf_matcher_type type,
                        enum bf_matcher_op op, const void *payload,
                        size_t payload_len)
{
    _free_bf_matcher_ struct bf_matcher *matcher = NULL;
    int r;

    bf_assert(rule);

    r = bf_matcher_new(&matcher, type, op, payload, payload_len);
    if (r)
        return r;

    r = bf_list_add_tail(&rule->matchers, matcher);
    if (r)
        return r;

    TAKE_PTR(matcher);

    return 0;
}
