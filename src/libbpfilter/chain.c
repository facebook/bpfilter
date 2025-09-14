/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/chain.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bpfilter/dump.h"
#include "bpfilter/helper.h"
#include "bpfilter/hook.h"
#include "bpfilter/list.h"
#include "bpfilter/logger.h"
#include "bpfilter/pack.h"
#include "bpfilter/rule.h"
#include "bpfilter/set.h"
#include "bpfilter/verdict.h"

static void _bf_chain_update_features(struct bf_chain *chain,
                                      const struct bf_rule *rule)
{
    bf_assert(rule);

    if (rule->log)
        chain->flags |= BF_FLAG(BF_CHAIN_LOG);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        if (bf_matcher_get_type(matcher) == BF_MATCHER_IP6_NEXTHDR) {
            chain->flags |= BF_FLAG(BF_CHAIN_STORE_NEXTHDR);
            break;
        }
    }
}

int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    size_t ridx = 0;

    bf_assert(chain && name);
    bf_assert(policy < _BF_TERMINAL_VERDICT_MAX);

    _chain = malloc(sizeof(*_chain));
    if (!_chain)
        return -ENOMEM;

    _chain->name = strdup(name);
    if (!_chain->name)
        return -ENOMEM;

    _chain->flags = 0;
    _chain->hook = hook;
    _chain->policy = policy;

    _chain->sets = bf_list_default(bf_set_free, bf_set_pack);
    if (sets)
        _chain->sets = bf_list_move(*sets);

    _chain->rules = bf_list_default(bf_rule_free, bf_rule_pack);
    if (rules)
        _chain->rules = bf_list_move(*rules);
    bf_list_foreach (&_chain->rules, rule_node) {
        struct bf_rule *rule = bf_list_node_get_data(rule_node);

        rule->index = ridx++;
        _bf_chain_update_features(_chain, rule);
    }

    *chain = TAKE_PTR(_chain);

    return 0;
}

int bf_chain_new_from_pack(struct bf_chain **chain, bf_rpack_node_t node)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    _cleanup_free_ char *name = NULL;
    enum bf_hook hook;
    enum bf_verdict policy;
    bf_rpack_node_t array, array_node;
    bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    bf_list sets = bf_list_default(bf_set_free, bf_set_pack);
    int r;

    r = bf_rpack_kv_str(node, "name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.name");

    r = bf_rpack_kv_enum(node, "hook", &hook);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.hook");

    r = bf_rpack_kv_enum(node, "policy", &policy);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.policy");

    r = bf_rpack_kv_array(node, "sets", &array);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.sets");
    bf_rpack_array_foreach (array, array_node) {
        _free_bf_set_ struct bf_set *set = NULL;

        r = bf_list_emplace(&sets, bf_set_new_from_pack, set, array_node);
        if (r) {
            return bf_err_r(r, "failed to unpack bf_set into bf_chain.sets");
        }
    }

    r = bf_rpack_kv_array(node, "rules", &array);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.rules");
    bf_rpack_array_foreach (array, array_node) {
        _free_bf_rule_ struct bf_rule *rule = NULL;

        r = bf_list_emplace(&rules, bf_rule_new_from_pack, rule, array_node);
        if (r) {
            return bf_err_r(r, "failed to unpack bf_rule into bf_chain.rules");
        }
    }

    r = bf_chain_new(&_chain, name, hook, policy, &sets, &rules);
    if (r)
        return bf_err_r(r, "failed to create bf_chain from pack");

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

int bf_chain_pack(const struct bf_chain *chain, bf_wpack_t *pack)
{
    bf_assert(chain);
    bf_assert(pack);

    bf_wpack_kv_str(pack, "name", chain->name);
    bf_wpack_kv_enum(pack, "hook", chain->hook);
    bf_wpack_kv_enum(pack, "policy", chain->policy);

    bf_wpack_kv_list(pack, "sets", &chain->sets);
    bf_wpack_kv_list(pack, "rules", &chain->rules);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix)
{
    bf_assert(chain && prefix);

    DUMP(prefix, "struct bf_chain at %p", chain);
    bf_dump_prefix_push(prefix);

    DUMP(prefix, "name: %s", chain->name);
    DUMP(prefix, "flags: %02x", chain->flags);
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
    _bf_chain_update_features(chain, rule);

    return bf_list_add_tail(&chain->rules, rule);
}

struct bf_set *bf_chain_get_set_for_matcher(const struct bf_chain *chain,
                                            const struct bf_matcher *matcher)
{
    bf_assert(chain && matcher);

    uint32_t set_id;

    if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
        return NULL;

    set_id = *(uint32_t *)bf_matcher_payload(matcher);

    return bf_list_get_at(&chain->sets, set_id);
}
