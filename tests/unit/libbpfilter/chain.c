/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/chain.h>
#include <bpfilter/list.h>
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
    struct bf_matcher *r0_m0 = bf_list_node_get_data(bf_list_get_head(&r0->matchers));
    struct bf_matcher *r0_m2 = bf_list_node_get_data(bf_list_get_tail(&r0->matchers));

    struct bf_rule *r1 = bf_list_node_get_data(bf_list_node_next(bf_list_get_head(&chain->rules)));
    struct bf_matcher *r1_m0 = bf_list_node_get_data(bf_list_get_head(&r1->matchers));

    struct bf_rule *r5 = bf_list_node_get_data(bf_list_get_tail(&chain->rules));
    struct bf_matcher *r5_m0 = bf_list_node_get_data(bf_list_get_head(&r5->matchers));

    struct bf_list_node *snode = bf_list_get_head(&chain->sets);
    struct bf_set *set0 = bf_list_node_get_data(snode);
    struct bf_set *set1 = bf_list_node_get_data(bf_list_node_next(snode));
    struct bf_set *set2 = bf_list_node_get_data(bf_list_node_next(bf_list_node_next(snode)));

    (void)state;

    assert_ptr_equal(set0, bf_chain_get_set_for_matcher(chain, r0_m0));
    assert_ptr_equal(set1, bf_chain_get_set_for_matcher(chain, r0_m2));
    assert_ptr_equal(set2, bf_chain_get_set_for_matcher(chain, r5_m0));

    assert_null(bf_chain_get_set_for_matcher(chain, r1_m0));
}

static void validate(void **state)
{
    (void)state;

    {
        _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(true);

        assert_true(bf_chain_validate(chain));
    }

    {
        // Some hooks don't support setting the packet's mark

        _free_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_rule_ struct bf_rule *rule = bft_rule_dummy(1);
        enum bf_hook hooks[] = {
            BF_HOOK_XDP, BF_HOOK_NF_PRE_ROUTING, BF_HOOK_NF_POST_ROUTING, BF_HOOK_NF_FORWARD, BF_HOOK_NF_LOCAL_IN, BF_HOOK_NF_LOCAL_OUT
        };

        bf_rule_mark_set(rule, 8);

        assert_ok(bf_chain_new(&chain, "chain", BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL, NULL));
        assert_ok(bf_chain_add_rule(chain, rule));
        TAKE_PTR(rule);

        for (size_t i = 0; i < ARRAY_SIZE(hooks); ++i) {
            chain->hook = hooks[i];
            assert_false(bf_chain_validate(chain));
        }
    }

    {
        // Some hooks can't read the packet's mark

        _free_bf_chain_ struct bf_chain *chain = NULL;
        _free_bf_rule_ struct bf_rule *rule = bft_rule_dummy(0);
        uint32_t mark = 8;

        assert_ok(bf_rule_add_matcher(rule, BF_MATCHER_META_MARK, BF_MATCHER_EQ, &mark, sizeof(mark)));

        assert_ok(bf_chain_new(&chain, "chain", BF_HOOK_XDP, BF_VERDICT_ACCEPT, NULL, NULL));
        assert_ok(bf_chain_add_rule(chain, rule));
        TAKE_PTR(rule);

        assert_false(bf_chain_validate(chain));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(dump),
        cmocka_unit_test(get_set_from_matcher),
        cmocka_unit_test(validate),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
