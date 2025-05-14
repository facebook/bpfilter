/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "chain.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/marsh.h"
#include "core/rule.h"
#include "core/set.h"
#include "core/verdict.h"

int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;

    bf_assert(policy < _BF_TERMINAL_VERDICT_MAX);

    _chain = malloc(sizeof(*_chain));
    if (!_chain)
        return -ENOMEM;

    _chain->name = strdup(name);
    if (!_chain->name)
        return -ENOMEM;

    _chain->hook = hook;
    _chain->policy = policy;

    _chain->sets = bf_list_default(bf_set_free, bf_set_marsh);
    if (sets)
        _chain->sets = bf_list_move(*sets);

    _chain->rules = bf_list_default(bf_rule_free, bf_rule_marsh);
    if (rules)
        _chain->rules = bf_list_move(*rules);

    *chain = TAKE_PTR(_chain);

    return 0;
}

int bf_chain_new_from_marsh(struct bf_chain **chain,
                            const struct bf_marsh *marsh)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    struct bf_marsh *child = NULL;
    struct bf_marsh *list_elem;
    enum bf_hook hook;
    enum bf_verdict policy;
    _cleanup_free_ const char *name = NULL;
    int r;

    bf_assert(chain && marsh);

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    if (child->data_len == 0)
        return bf_err_r(-EINVAL, "serialized bf_chain.name is empty");
    name = strdup(child->data);
    if (!name)
        return -ENOMEM;

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&hook, child->data, sizeof(hook));

    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    memcpy(&policy, child->data, sizeof(policy));

    r = bf_chain_new(&_chain, name, hook, policy, NULL, NULL);
    if (r)
        return r;

    // Unmarsh bf_chain.sets
    list_elem = NULL;
    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    while ((list_elem = bf_marsh_next_child(child, list_elem))) {
        _free_bf_set_ struct bf_set *set = NULL;

        r = bf_set_new_from_marsh(&set, list_elem);
        if (r)
            return r;

        r = bf_list_add_tail(&_chain->sets, set);
        if (r)
            return r;

        TAKE_PTR(set);
    }

    // Unmarsh bf_chain.rules
    list_elem = NULL;
    if (!(child = bf_marsh_next_child(marsh, child)))
        return -EINVAL;
    while ((list_elem = bf_marsh_next_child(child, list_elem))) {
        _free_bf_rule_ struct bf_rule *rule = NULL;

        r = bf_rule_unmarsh(list_elem, &rule);
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

    bf_list_clean(&(*chain)->sets);
    bf_list_clean(&(*chain)->rules);
    freep((void *)&(*chain)->name);
    freep((void *)chain);
}

int bf_chain_marsh(const struct bf_chain *chain, struct bf_marsh **marsh)
{
    _free_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(chain && marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, chain->name, strlen(chain->name) + 1);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &chain->hook, sizeof(chain->hook));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &chain->policy, sizeof(chain->policy));
    if (r)
        return r;

    {
        // Serialize bf_chain.sets
        _free_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_list_marsh(&chain->sets, &child);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r < 0)
            return r;
    }

    {
        // Serialize bf_chain.rules
        _free_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_list_marsh(&chain->rules, &child);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r < 0)
            return r;
    }

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix)
{
    bf_assert(chain && prefix);

    DUMP(prefix, "struct bf_chain at %p", chain);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: %s", chain->name);
    DUMP(prefix, "hook: %s", bf_hook_to_str(chain->hook));
    DUMP(prefix, "policy: %s", bf_verdict_to_str(chain->policy));

    DUMP(prefix, "sets: bf_list<bf_set>[%lu]", bf_list_size(&chain->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&chain->sets, set_node) {
        if (bf_list_is_tail(&chain->sets, set_node))
            bf_dump_prefix_last(prefix);

        bf_set_dump(bf_list_node_get_data(set_node), prefix);
    }
    bf_dump_prefix_pop(prefix);

    DUMP(bf_dump_prefix_last(prefix), "rules: bf_list<bf_rule>[%lu]",
         bf_list_size(&chain->rules));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&chain->rules, rule_node) {
        if (bf_list_is_tail(&chain->rules, rule_node))
            bf_dump_prefix_last(prefix);

        bf_rule_dump(bf_list_node_get_data(rule_node), prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_chain_add_rule(struct bf_chain *chain, struct bf_rule *rule)
{
    bf_assert(chain && rule);

    rule->index = bf_list_size(&chain->rules);

    return bf_list_add_tail(&chain->rules, rule);
}
