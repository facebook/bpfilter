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

int bf_chain_new(struct bf_chain **chain, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules)
{
    _cleanup_bf_chain_ struct bf_chain *_chain = NULL;
    int r;

    bf_assert(chain);

    _chain = malloc(sizeof(*_chain));
    if (!_chain)
        return -ENOMEM;

    _chain->hook = hook;
    _chain->hook_opts = (struct bf_hook_opts) {};
    _chain->policy = policy;

    _chain->sets = bf_set_list();
    if (sets)
        bf_swap(_chain->sets, *sets);

    _chain->rules = bf_rule_list();
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
    struct bf_marsh *chain_elem = NULL;
    struct bf_marsh *list_elem = NULL;
    enum bf_hook hook;
    enum bf_verdict policy;
    int r;

    bf_assert(chain);
    bf_assert(marsh);

    if (!(chain_elem = bf_marsh_next_child(marsh, chain_elem)))
        return -EINVAL;
    memcpy(&hook, chain_elem->data, sizeof(hook));

    if (!(chain_elem = bf_marsh_next_child(marsh, chain_elem)))
        return -EINVAL;
    memcpy(&policy, chain_elem->data, sizeof(policy));

    r = bf_chain_new(&_chain, hook, policy, NULL, NULL);
    if (r)
        return r;

    // Unmarsh bf_chain.hook_opts
    if (!(chain_elem = bf_marsh_next_child(marsh, chain_elem)))
        return -EINVAL;
    {
        if (!(list_elem = bf_marsh_next_child(chain_elem, NULL)))
            return -EINVAL;
        memcpy(&_chain->hook_opts.used_opts, list_elem->data,
               sizeof(_chain->hook_opts.used_opts));

        if (!(list_elem = bf_marsh_next_child(chain_elem, list_elem)))
            return -EINVAL;
        memcpy(&_chain->hook_opts.ifindex, list_elem->data,
               sizeof(_chain->hook_opts.ifindex));

        if (!(list_elem = bf_marsh_next_child(chain_elem, list_elem)))
            return -EINVAL;

        if (list_elem->data_len) {
            _chain->hook_opts.cgroup = strdup(list_elem->data);
            if (!_chain->hook_opts.cgroup)
                return -ENOMEM;
        }

        if (bf_marsh_next_child(chain_elem, list_elem)) {
            return bf_err_r(-E2BIG,
                            "too many serialized fields for bf_hook_opts");
        }
    }

    // Unmarsh bf_chain.sets
    if (!(chain_elem = bf_marsh_next_child(marsh, chain_elem)))
        return -EINVAL;

    list_elem = NULL;
    while ((list_elem = bf_marsh_next_child(chain_elem, list_elem))) {
        _cleanup_bf_set_ struct bf_set *set = NULL;

        r = bf_set_new_from_marsh(&set, list_elem);
        if (r)
            return r;

        r = bf_list_add_tail(&_chain->sets, set);
        if (r)
            return r;

        TAKE_PTR(set);
    }

    // Unmarsh bf_chain.rules
    if (!(chain_elem = bf_marsh_next_child(marsh, chain_elem)))
        return -EINVAL;
    list_elem = NULL;
    while ((list_elem = bf_marsh_next_child(chain_elem, list_elem))) {
        _cleanup_bf_rule_ struct bf_rule *rule = NULL;

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
    bf_hook_opts_clean(&(*chain)->hook_opts);
    freep((void *)chain);
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

    r = bf_marsh_add_child_raw(&_marsh, &chain->hook, sizeof(chain->hook));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &chain->policy, sizeof(chain->policy));
    if (r)
        return r;

    {
        // Serialize bf_chain.hook_opts
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;
        const char *cg_path = chain->hook_opts.cgroup;

        r = bf_marsh_new(&child, NULL, 0);
        if (r < 0)
            return bf_err_r(r, "failed to creaet marsh for bf_chain");

        r = bf_marsh_add_child_raw(&child, &chain->hook_opts.used_opts,
                                   sizeof(chain->hook_opts.used_opts));
        if (r < 0)
            return r;

        r = bf_marsh_add_child_raw(&child, &chain->hook_opts.ifindex,
                                   sizeof(chain->hook_opts.ifindex));
        if (r)
            return r;

        /* If a cgroup path is defined, serialize it, including the nul
         * termination character (to simplify deserializing with strdup()).
         * Otherwise, create an empty child marsh (NULL data and 0 length). */
        r = bf_marsh_add_child_raw(&child, cg_path,
                                   cg_path ? strlen(cg_path) + 1 : 0);
        if (r)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r < 0)
            return r;
    }

    {
        // Serialize bf_chain.sets
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

        r = bf_list_marsh(&chain->sets, &child);
        if (r < 0)
            return r;

        r = bf_marsh_add_child_obj(&_marsh, child);
        if (r < 0)
            return r;
    }

    {
        // Serialize bf_chain.rules
        _cleanup_bf_marsh_ struct bf_marsh *child = NULL;

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
    bf_assert(chain);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_chain at %p", chain);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "hook: %s", bf_hook_to_str(chain->hook));
    DUMP(prefix, "hook_opts: struct bf_hook_opts");
    bf_hook_opts_dump(&chain->hook_opts, prefix, chain->hook);
    DUMP(prefix, "policy: %s", bf_verdict_to_str(chain->policy));

    DUMP(prefix, "sets: bf_list<bf_set>[%lu]", bf_list_size(&chain->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);

        if (bf_list_is_tail(&chain->sets, set_node))
            bf_dump_prefix_last(prefix);

        bf_set_dump(set, prefix);
    }
    bf_dump_prefix_pop(prefix);

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
