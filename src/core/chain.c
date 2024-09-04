/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "chain.h"

#include "core/marsh.h"
#include "core/rule.h"
#include "shared/helper.h"

int bf_chain_new(struct bf_chain **chain, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *rules)
{
    _cleanup_bf_chain_ struct bf_chain *_chain = NULL;
    int r;

    bf_assert(chain);

    _chain = malloc(sizeof(*_chain));
    if (!_chain)
        return -ENOMEM;

    _chain->hook = hook;
    _chain->policy = policy;

    bf_list_init(&_chain->rules,
                 (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_rule_free}});

    if (rules) {
        bf_list_foreach (rules, rule_node) {
            r = bf_list_add_tail(&_chain->rules,
                                 bf_list_node_get_data(rule_node));
            if (r)
                return r;

            bf_list_node_take_data(rule_node);
        }
    }

    *chain = TAKE_PTR(_chain);

    return 0;
}

int bf_chain_new_from_marsh(struct bf_chain **chain,
                            const struct bf_marsh *marsh)
{
    _cleanup_bf_chain_ struct bf_chain *_chain = NULL;
    struct bf_marsh *child = NULL;
    struct bf_marsh *subchild = NULL;
    enum bf_hook hook;
    enum bf_verdict policy;
    int r;

    bf_assert(chain);
    bf_assert(marsh);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&hook, child->data, sizeof(hook));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&policy, child->data, sizeof(policy));

    r = bf_chain_new(&_chain, hook, policy, NULL);
    if (r)
        return r;

    // Unmarsh bf_chain.rules
    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    subchild = NULL;
    while ((subchild = bf_marsh_next_child(child, subchild))) {
        _cleanup_bf_rule_ struct bf_rule *rule = NULL;

        r = bf_rule_unmarsh(subchild, &rule);
        if (r)
            return r;

        r = bf_list_add_tail(&_chain->rules, rule);
        if (r)
            return r;

        TAKE_PTR(rule);
    }

    *chain = TAKE_PTR(_chain);

    return 0;
}

void bf_chain_free(struct bf_chain **chain)
{
    bf_assert(chain);

    if (!*chain)
        return;

    bf_list_clean(&(*chain)->rules);
    freep(chain);
}

int bf_chain_marsh(const struct bf_chain *chain, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(chain);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    r |= bf_marsh_add_child_raw(&_marsh, &chain->hook, sizeof(chain->hook));
    r |= bf_marsh_add_child_raw(&_marsh, &chain->policy, sizeof(chain->policy));
    if (r)
        return r;

    {
        // Serialize bf_chain.rules
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_marsh_new(&child, NULL, 0);
        if (r < 0)
            return bf_err_code(r, "failed to create marsh for bf_chain");

        bf_list_foreach (&chain->rules, rule_node) {
            _cleanup_bf_marsh_ struct bf_marsh *subchild = NULL;

            r = bf_rule_marsh(bf_list_node_get_data(rule_node), &subchild);
            if (r < 0)
                return r;

            r = bf_marsh_add_child_obj(&child, subchild);
            if (r < 0)
                return r;
        }

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r < 0)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix)
{
    bf_assert(chain);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_chain at %p", chain);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "hook: %s", bf_hook_to_str(chain->hook));
    DUMP(prefix, "policy: %s", bf_verdict_to_str(chain->policy));
    DUMP(bf_dump_prefix_last(prefix), "rules: bf_list<bf_rule>[%lu]",
         bf_list_size(&chain->rules));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        if (bf_list_is_tail(&chain->rules, rule_node))
            bf_dump_prefix_last(prefix);

        bf_rule_dump(rule, prefix);
    }

    bf_dump_prefix_pop(prefix);
    bf_dump_prefix_pop(prefix);
}

int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule)
{
    bf_assert(chain);
    bf_assert(rule);

    return bf_list_add_tail(&chain->rules, rule);
}
