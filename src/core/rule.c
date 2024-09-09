/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "core/rule.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/matcher.h"
#include "core/verdict.h"

int bf_rule_new(struct bf_rule **rule)
{
    struct bf_rule *_rule;

    bf_assert(rule);

    _rule = calloc(1, sizeof(*_rule));
    if (!_rule)
        return -ENOMEM;

    bf_list_init(&_rule->matchers,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_matcher_free}});

    *rule = _rule;

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

int bf_rule_marsh(const struct bf_rule *rule, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(rule);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &rule->index, sizeof(rule->index));
    r |= bf_marsh_add_child_raw(&_marsh, &rule->ifindex, sizeof(rule->ifindex));
    if (r)
        return r;

    {
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
        r = bf_marsh_new(&child, NULL, 0);
        if (r)
            return r;

        bf_list_foreach (&rule->matchers, matcher_node) {
            _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;
            struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);

            r = bf_matcher_marsh(matcher, &subchild);
            if (r)
                return r;

            r = bf_marsh_add_child_obj(&child, subchild);
            if (r)
                return r;
        }

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r)
            return r;
    }

    r |= bf_marsh_add_child_raw(&_marsh, &rule->counters,
                                sizeof(rule->counters));
    r |= bf_marsh_add_child_raw(&_marsh, &rule->verdict,
                                sizeof(enum bf_verdict));
    if (r)
        return bf_err_r(r, "Failed to serialize rule");

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

int bf_rule_unmarsh(const struct bf_marsh *marsh, struct bf_rule **rule)
{
    _cleanup_bf_rule_ struct bf_rule *_rule = NULL;
    struct bf_marsh *rule_elem = NULL;
    int r;

    bf_assert(marsh);
    bf_assert(rule);

    r = bf_rule_new(&_rule);
    if (r < 0)
        return r;

    if (!(rule_elem = bf_marsh_next_child(marsh, NULL)))
        return -EINVAL;
    memcpy(&_rule->index, rule_elem->data, sizeof(_rule->index));

    if (!(rule_elem = bf_marsh_next_child(marsh, rule_elem)))
        return -EINVAL;
    memcpy(&_rule->ifindex, rule_elem->data, sizeof(_rule->ifindex));

    if (!(rule_elem = bf_marsh_next_child(marsh, rule_elem)))
        return -EINVAL;

    {
        struct bf_marsh *matcher_elem = NULL;

        while ((matcher_elem = bf_marsh_next_child(rule_elem, matcher_elem))) {
            _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;

            r = bf_matcher_new_from_marsh(&matcher, matcher_elem);
            if (r)
                return r;

            r = bf_list_add_tail(&_rule->matchers, matcher);
            if (r)
                return r;

            TAKE_PTR(matcher);
        }
    }

    if (!(rule_elem = bf_marsh_next_child(marsh, rule_elem)))
        return -EINVAL;
    memcpy(&_rule->counters, rule_elem->data, sizeof(_rule->counters));

    if (!(rule_elem = bf_marsh_next_child(marsh, rule_elem)))
        return -EINVAL;
    memcpy(&_rule->verdict, rule_elem->data, sizeof(_rule->verdict));

    if (bf_marsh_next_child(marsh, rule_elem))
        bf_warn("codegen marsh has more children than expected");

    *rule = TAKE_PTR(_rule);

    return 0;
}

void bf_rule_dump(const struct bf_rule *rule, prefix_t *prefix)
{
    bf_assert(rule);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_rule at %p", rule);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "index: %u", rule->index);
    DUMP(prefix, "ifindex: %u", rule->ifindex);

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

    DUMP(prefix, "counters: %s", rule->counters ? "yes" : "no");
    DUMP(bf_dump_prefix_last(prefix), "verdict: %s",
         bf_verdict_to_str(rule->verdict));

    bf_dump_prefix_pop(prefix);
}

int bf_rule_add_matcher(struct bf_rule *rule, enum bf_matcher_type type,
                        enum bf_matcher_op op, const void *payload,
                        size_t payload_len)
{
    _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;
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
