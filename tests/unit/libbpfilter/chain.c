/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/pack.h>
#include <bpfilter/rule.h>
#include <bpfilter/runtime.h>
#include <bpfilter/set.h>

#include "bpfilter/matcher.h"
#include "fake.h"
#include "test.h"

static void new_and_free(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    size_t i = 0;

    (void)state;

    assert_ok(bf_chain_new(&chain, "name", 0, 0, NULL, NULL));
    bf_chain_free(&chain);
    assert_null(chain);

    assert_ok(bf_list_add_tail(&rules, bft_rule_dummy(0)));
    assert_ok(bf_list_add_tail(&rules, bft_rule_dummy(0)));

    assert_ok(bf_chain_new(&chain, "name", 0, 0, NULL, &rules));
    bf_list_foreach (&chain->rules, rule_node) {
        assert_int_equal(
            i++, ((struct bf_rule *)(bf_list_node_get_data(rule_node)))->index);
    }
}

static void pack_and_unpack(void **state)
{
    _free_bf_chain_ struct bf_chain *chain0 = NULL;
    _free_bf_chain_ struct bf_chain *chain1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_non_null(chain0 = bft_chain_dummy(false));

    assert_ok(bf_wpack_new(&wpack));
    assert_ok(bf_chain_pack(chain0, wpack));
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_chain_new_from_pack(&chain1, bf_rpack_root(rpack)));

    assert_true(bft_chain_equal(chain0, chain1));
}

static void dump(void **state)
{
    _free_bf_chain_ struct bf_chain *chain0 = bft_chain_dummy(false);
    _free_bf_chain_ struct bf_chain *chain1 = bft_chain_dummy(true);

    (void)state;

    assert_non_null(chain0);
    assert_non_null(chain1);

    bf_chain_dump(chain0, EMPTY_PREFIX);
    bf_chain_dump(chain1, EMPTY_PREFIX);
}

static void get_set_from_matcher(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);
    struct bf_rule *r0 = bf_list_node_get_data(bf_list_get_head(&chain->rules));
    struct bf_matcher *r0_m0 =
        bf_list_node_get_data(bf_list_get_head(&r0->matchers));
    struct bf_matcher *r0_m2 =
        bf_list_node_get_data(bf_list_get_tail(&r0->matchers));

    struct bf_rule *r1 = bf_list_node_get_data(
        bf_list_node_next(bf_list_get_head(&chain->rules)));
    struct bf_matcher *r1_m0 =
        bf_list_node_get_data(bf_list_get_head(&r1->matchers));

    struct bf_rule *r5 = bf_list_node_get_data(bf_list_get_tail(&chain->rules));
    struct bf_matcher *r5_m0 =
        bf_list_node_get_data(bf_list_get_head(&r5->matchers));

    struct bf_list_node *snode = bf_list_get_head(&chain->sets);
    struct bf_set *set0 = bf_list_node_get_data(snode);
    struct bf_set *set1 = bf_list_node_get_data(bf_list_node_next(snode));
    struct bf_set *set2 =
        bf_list_node_get_data(bf_list_node_next(bf_list_node_next(snode)));

    (void)state;

    assert_ptr_equal(set0, bf_chain_get_set_for_matcher(chain, r0_m0));
    assert_ptr_equal(set1, bf_chain_get_set_for_matcher(chain, r0_m2));
    assert_ptr_equal(set2, bf_chain_get_set_for_matcher(chain, r5_m0));

    assert_null(bf_chain_get_set_for_matcher(chain, r1_m0));
}

static void mixed_enabled_disabled_log_flag(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, bf_set_pack);
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    struct bf_rule *r0 = NULL;
    struct bf_rule *r1 = NULL;
    uint32_t set_index;

    (void)state;

    assert_ok(bf_list_add_tail(&sets, bft_set_dummy(0)));
    assert_ok(bf_list_add_tail(&sets, bft_set_dummy(4)));

    set_index = 0;
    assert_ok(bf_rule_new(&r0));
    r0->log = 1;
    assert_ok(bf_rule_add_matcher(r0, BF_MATCHER_SET, BF_MATCHER_IN, &set_index,
                                  sizeof(set_index)));
    assert_ok(bf_list_add_tail(&rules, r0));

    set_index = 1;
    assert_ok(bf_rule_new(&r1));
    assert_ok(bf_rule_add_matcher(r1, BF_MATCHER_SET, BF_MATCHER_IN, &set_index,
                                  sizeof(set_index)));
    assert_ok(bf_list_add_tail(&rules, r1));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS, BF_VERDICT_ACCEPT,
                           &sets, &rules));

    assert_true(r0->disabled);
    assert_false(r1->disabled);
    assert_int_equal(chain->flags & BF_FLAG(BF_CHAIN_LOG), 0);
}

static void incompatible_matchers_disable_rule(void **state)
{
    (void)state;

    // L3 conflict: IPv4 + IPv6 matchers.
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint32_t ip4_addr = 0;
        uint8_t ip6_addr[16] = {};

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                      &ip4_addr, sizeof(ip4_addr)));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                                      ip6_addr, sizeof(ip6_addr)));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_true(rule->disabled);
    }

    // L4 conflict: TCP + UDP matchers.
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint16_t port = 0;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port)));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_UDP_DPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port)));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_true(rule->disabled);
    }

    // L3 conflict via set: ip4.daddr set + ip6.daddr matcher.
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list sets =
            bf_list_default(bf_set_free, bf_set_pack);
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        _free_bf_set_ struct bf_set *set = NULL;
        struct bf_rule *rule = NULL;

        enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR};

        uint32_t set_index = 0;
        uint8_t ip6_addr[16] = {};

        assert_ok(bf_set_new(&set, "s", key, ARRAY_SIZE(key)));
        assert_ok(bf_set_add_elem(set, (uint8_t[4]) {10, 0, 0, 1}));
        assert_ok(bf_list_add_tail(&sets, set));
        set = NULL;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_SET, BF_MATCHER_IN,
                                      &set_index, sizeof(set_index)));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP6_DADDR, BF_MATCHER_EQ,
                                      ip6_addr, sizeof(ip6_addr)));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, &sets, &rules));
        assert_true(rule->disabled);
    }

    // No conflict: same protocol at same layer (TCP sport + TCP dport).
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint16_t port = 0;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port)));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_DPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port)));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_false(rule->disabled);
    }

    // No conflict: different layers (IPv4 + TCP).
    {
        _free_bf_chain_ struct bf_chain *chain = NULL;
        _clean_bf_list_ bf_list rules =
            bf_list_default(bf_rule_free, bf_rule_pack);
        struct bf_rule *rule = NULL;
        uint32_t ip4_addr = 0;
        uint16_t port = 0;

        assert_ok(bf_rule_new(&rule));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_IP4_SADDR, BF_MATCHER_EQ,
                                      &ip4_addr, sizeof(ip4_addr)));
        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_TCP_SPORT, BF_MATCHER_EQ,
                                      &port, sizeof(port)));
        assert_ok(bf_list_add_tail(&rules, rule));

        assert_ok(bf_chain_new(&chain, "test", BF_HOOK_TC_EGRESS,
                               BF_VERDICT_ACCEPT, NULL, &rules));
        assert_false(rule->disabled);
    }
}

static void policy_validation(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;

    (void)state;

    assert_ok(bf_chain_new(&chain, "next", BF_HOOK_TC_EGRESS, BF_VERDICT_NEXT,
                           NULL, NULL));
    bf_chain_free(&chain);

    assert_err(bf_chain_new(&chain, "bad", BF_HOOK_TC_EGRESS,
                            BF_VERDICT_CONTINUE, NULL, NULL));
    assert_err(bf_chain_new(&chain, "bad", BF_HOOK_TC_EGRESS,
                            BF_VERDICT_REDIRECT, NULL, NULL));
}

static void set_component_unsupported_hook(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, bf_set_pack);
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, bf_rule_pack);
    _free_bf_set_ struct bf_set *set = NULL;
    struct bf_rule *rule = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t set_index = 0;

    (void)state;

    // Set component unsupported for hook: ip4.saddr on CONNECT4.
    assert_ok(bf_set_new(&set, "s", key, ARRAY_SIZE(key)));
    assert_ok(bf_set_add_elem(set, (uint8_t[4]) {10, 0, 0, 1}));
    assert_ok(bf_list_add_tail(&sets, set));
    set = NULL;

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_SET, BF_MATCHER_IN,
                                  &set_index, sizeof(set_index)));
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_err(bf_chain_new(&chain, "test", BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                            BF_VERDICT_ACCEPT, &sets, &rules));

    // Supported component: ip4.daddr on CONNECT4 should succeed.
    bf_list_clean(&sets);
    bf_list_clean(&rules);

    enum bf_matcher_type daddr_key[] = {BF_MATCHER_IP4_DADDR};

    assert_ok(bf_set_new(&set, "s2", daddr_key, ARRAY_SIZE(daddr_key)));
    assert_ok(bf_set_add_elem(set, (uint8_t[4]) {10, 0, 0, 1}));
    assert_ok(bf_list_add_tail(&sets, set));
    set = NULL;

    assert_ok(bf_rule_new(&rule));
    assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_SET, BF_MATCHER_IN,
                                  &set_index, sizeof(set_index)));
    assert_ok(bf_list_add_tail(&rules, rule));

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_CGROUP_SOCK_ADDR_CONNECT4,
                           BF_VERDICT_ACCEPT, &sets, &rules));
}

static void get_set_by_name(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);

    (void)state;

    assert_non_null(bf_chain_get_set_by_name(chain, "bft_set_dummy"));
    assert_null(bf_chain_get_set_by_name(chain, "bft_set_missing"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(dump),
        cmocka_unit_test(get_set_from_matcher),
        cmocka_unit_test(mixed_enabled_disabled_log_flag),
        cmocka_unit_test(incompatible_matchers_disable_rule),
        cmocka_unit_test(policy_validation),
        cmocka_unit_test(set_component_unsupported_hook),
        cmocka_unit_test(get_set_by_name),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
