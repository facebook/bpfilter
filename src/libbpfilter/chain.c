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

/**
 * @brief Check if a rule references an empty set.
 *
 * @param chain Chain containing the sets list.
 * @param rule Rule to check.
 * @return 0 if no issues, 1 if rule references an empty set (should be
 *         disabled), or negative errno if rule references a non-existent set.
 */
static int _bf_rule_references_empty_set(const struct bf_chain *chain,
                                         const struct bf_rule *rule)
{
    assert(chain);
    assert(rule);

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        uint32_t set_index;
        struct bf_set *set;

        if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
            continue;

        set_index = *(uint32_t *)bf_matcher_payload(matcher);
        set = bf_list_get_at(&chain->sets, set_index);

        if (!set) {
            return bf_err_r(-EINVAL, "rule %u references non-existent set",
                            rule->index);
        }

        if (bf_set_is_empty(set)) {
            bf_warn("rule %u references empty set, rule will be disabled",
                    rule->index);
            return 1;
        }
    }
    return 0;
}

int _bf_chain_check_rule(struct bf_chain *chain, struct bf_rule *rule)
{
    int r;

    assert(rule);

    r = _bf_rule_references_empty_set(chain, rule);
    if (r < 0)
        return r;

    rule->disabled = r;

    if (rule->log && !rule->disabled)
        chain->flags |= BF_FLAG(BF_CHAIN_LOG);

    if (bf_rule_mark_is_set(rule) &&
        (chain->hook == BF_HOOK_XDP || chain->hook == BF_HOOK_NF_PRE_ROUTING ||
         chain->hook == BF_HOOK_NF_POST_ROUTING ||
         chain->hook == BF_HOOK_NF_FORWARD ||
         chain->hook == BF_HOOK_NF_LOCAL_IN ||
         chain->hook == BF_HOOK_NF_LOCAL_OUT)) {
        return bf_err_r(-EINVAL,
                        "XDP and Netfilter chains can't set packet mark");
    }

    bf_list_foreach (&rule->matchers, matcher_node) {
        struct bf_matcher *matcher = bf_list_node_get_data(matcher_node);
        const struct bf_matcher_meta *meta;

        // Track if the chain uses IPv6 nexthdr matcher.
        if (bf_matcher_get_type(matcher) == BF_MATCHER_IP6_NEXTHDR &&
            !rule->disabled)
            chain->flags |= BF_FLAG(BF_CHAIN_STORE_NEXTHDR);

        // Set matchers are compatible with all hooks.
        if (bf_matcher_get_type(matcher) == BF_MATCHER_SET)
            continue;

        // Ensure the matcher is compatible with the chain's hook.
        meta = bf_matcher_get_meta(bf_matcher_get_type(matcher));
        if (!meta) {
            return bf_err_r(-EINVAL, "unknown matcher type %d in rule",
                            bf_matcher_get_type(matcher));
        }

        if (meta->unsupported_hooks & BF_FLAG(chain->hook)) {
            return bf_err_r(
                -ENOTSUP, "matcher %s is not compatible with %s",
                bf_matcher_type_to_str(bf_matcher_get_type(matcher)),
                bf_hook_to_str(chain->hook));
        }
    }

    return 0;
}

int bf_chain_new(struct bf_chain **chain, const char *name, enum bf_hook hook,
                 enum bf_verdict policy, bf_list *sets, bf_list *rules)
{
    _free_bf_chain_ struct bf_chain *_chain = NULL;
    size_t ridx = 0;
    int r;

    assert(chain && name);
    if (hook >= _BF_HOOK_MAX)
        return bf_err_r(-EINVAL, "unknown hook type");
    if (policy >= _BF_TERMINAL_VERDICT_MAX)
        return bf_err_r(-EINVAL, "unknown policy type");

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
        r = _bf_chain_check_rule(_chain, rule);
        if (r)
            return r;
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

    r = bf_rpack_kv_enum(node, "hook", &hook, 0, _BF_HOOK_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_chain.hook");

    r = bf_rpack_kv_enum(node, "policy", &policy, 0, _BF_TERMINAL_VERDICT_MAX);
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
    assert(chain);

    if (!*chain)
        return;

    bf_list_clean(&(*chain)->sets);
    bf_list_clean(&(*chain)->rules);
    freep((void *)&(*chain)->name);
    freep((void *)chain);
}

int bf_chain_pack(const struct bf_chain *chain, bf_wpack_t *pack)
{
    assert(chain);
    assert(pack);

    bf_wpack_kv_str(pack, "name", chain->name);
    bf_wpack_kv_enum(pack, "hook", chain->hook);
    bf_wpack_kv_enum(pack, "policy", chain->policy);

    bf_wpack_kv_list(pack, "sets", &chain->sets);
    bf_wpack_kv_list(pack, "rules", &chain->rules);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_chain_dump(const struct bf_chain *chain, prefix_t *prefix)
{
    assert(chain);
    assert(prefix);

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
    int r;

    assert(chain);
    assert(rule);

    rule->index = bf_list_size(&chain->rules);
    r = _bf_chain_check_rule(chain, rule);
    if (r)
        return r;

    return bf_list_add_tail(&chain->rules, rule);
}

int bf_chain_add_set(struct bf_chain *chain, struct bf_set *set)
{
    assert(chain && set);

    return bf_list_add_tail(&chain->sets, set);
}

struct bf_set *bf_chain_get_set_for_matcher(const struct bf_chain *chain,
                                            const struct bf_matcher *matcher)
{
    assert(chain);
    assert(matcher);

    uint32_t set_id;

    if (bf_matcher_get_type(matcher) != BF_MATCHER_SET)
        return NULL;

    set_id = *(uint32_t *)bf_matcher_payload(matcher);

    return bf_list_get_at(&chain->sets, set_id);
}

struct bf_set *bf_chain_get_set_by_name(struct bf_chain *chain, const char *set_name)
{
    assert(chain);
    assert(set_name);

    bf_list_foreach (&chain->sets, set_node) {
        struct bf_set *set = bf_list_node_get_data(set_node);
        if (bf_streq(set->name, set_name))
            return set;
    }

    return NULL;
}

int bf_chain_new_from_copy(struct bf_chain **dest, const struct bf_chain *src)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    int r;

    assert(dest);
    assert(src);

    // For now, we do a copy by serializing and deserializing the struct.
    // @todo Implement deep copy to avoid serialization overhead.
    r = bf_wpack_new(&wpack);
    if (r)
        return bf_err_r(r, "failed to create wpack for chain serialization");

    r = bf_chain_pack(src, wpack);
    if (r)
        return bf_err_r(r, "failed to serialize chain");

    r = bf_wpack_get_data(wpack, &data, &data_len);
    if (r)
        return bf_err_r(r, "failed to get serialized chain data");

    r = bf_rpack_new(&rpack, data, data_len);
    if (r)
        return bf_err_r(r, "failed to create rpack for chain deserialization");

    r = bf_chain_new_from_pack(dest, bf_rpack_root(rpack));
    if (r)
        return bf_err_r(r, "failed to deserialize chain");

    return 0;
}
