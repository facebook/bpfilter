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

static void update_set(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;
    _free_bf_set_ struct bf_set *initial_set = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, NULL);
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};
    struct bf_set *chain_set;
    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;

    (void)state;

    assert_ok(bf_set_new(&initial_set, "test_set", key, 1));
    assert_ok(bf_set_add_elem(initial_set, &elem1));
    assert_ok(bf_list_add_tail(&sets, initial_set));
    TAKE_PTR(initial_set);

    assert_ok(bf_chain_new(&chain, "test_chain", BF_HOOK_XDP, BF_VERDICT_ACCEPT, &sets, &rules));

    chain_set = bf_list_node_get_data(bf_list_get_head(&chain->sets));
    assert_non_null(chain_set);
    assert_string_equal(chain_set->name, "test_set");
    assert_int_equal(bf_list_size(&chain_set->elems), 1);

    assert_ok(bf_set_new(&to_add, "test_set", key, 1));
    assert_ok(bf_set_add_elem(to_add, &elem2));
    assert_ok(bf_set_add_elem(to_add, &elem3));

    assert_ok(bf_chain_update_set(chain, "test_set", to_add, NULL));

    chain_set = bf_list_node_get_data(bf_list_get_head(&chain->sets));
    assert_non_null(chain_set);
    assert_string_equal(chain_set->name, "test_set");
    assert_int_equal(bf_list_size(&chain_set->elems), 3);
}

static void update_set_not_found(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, NULL);
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};
    uint32_t elem = 0x01010101;

    (void)state;

    assert_ok(bf_chain_new(&chain, "test_chain", BF_HOOK_XDP, BF_VERDICT_ACCEPT, &sets, &rules));

    assert_ok(bf_set_new(&to_add, "nonexistent_set", key, 1));
    assert_ok(bf_set_add_elem(to_add, &elem));

    assert_int_equal(bf_chain_update_set(chain, "nonexistent_set", to_add, NULL), -ENOENT);
}

static void update_set_key_mismatch(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *old_set = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, NULL);
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};
    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_SADDR, BF_MATCHER_IP4_PROTO};
    uint32_t elem1 = 0x01010101;
    struct {
        uint32_t addr;
        uint8_t proto;
    } elem2 = {0x01010101, 6};

    (void)state;

    assert_ok(bf_set_new(&old_set, "test_set", key1, 1));
    assert_ok(bf_set_add_elem(old_set, &elem1));
    assert_ok(bf_list_add_tail(&sets, old_set));
    TAKE_PTR(old_set);

    assert_ok(bf_chain_new(&chain, "test_chain", BF_HOOK_XDP, BF_VERDICT_ACCEPT, &sets, &rules));

    assert_ok(bf_set_new(&to_add, "test_set", key2, 2));
    assert_ok(bf_set_add_elem(to_add, &elem2));

    assert_int_equal(bf_chain_update_set(chain, "test_set", to_add, NULL), -EINVAL);
}

static void update_set_trie(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_set_ struct bf_set *old_set = NULL;
    _free_bf_set_ struct bf_set *to_add = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, NULL);
    _clean_bf_list_ bf_list rules = bf_list_default(bf_rule_free, NULL);
    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SNET};
    struct bf_set *chain_set;
    struct {
        uint32_t addr;
        uint32_t mask;
    } elem1 = {0x0a000000, 0xffffff00}, elem2 = {0xc0a80000, 0xffff0000},
      elem3 = {0xac100000, 0xfff00000};

    (void)state;

    assert_ok(bf_set_new(&old_set, "nets", key, 1));
    assert_true(old_set->use_trie);
    assert_ok(bf_set_add_elem(old_set, &elem1));
    assert_ok(bf_list_add_tail(&sets, old_set));
    TAKE_PTR(old_set);

    assert_ok(bf_chain_new(&chain, "test_chain", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                           &sets, &rules));

    chain_set = bf_list_node_get_data(bf_list_get_head(&chain->sets));
    assert_non_null(chain_set);
    assert_string_equal(chain_set->name, "nets");
    assert_true(chain_set->use_trie);
    assert_int_equal(bf_list_size(&chain_set->elems), 1);

    assert_ok(bf_set_new(&to_add, "nets", key, 1));
    assert_true(to_add->use_trie);
    assert_ok(bf_set_add_elem(to_add, &elem2));
    assert_ok(bf_set_add_elem(to_add, &elem3));

    assert_ok(bf_chain_update_set(chain, "nets", to_add, NULL));

    chain_set = bf_list_node_get_data(bf_list_get_head(&chain->sets));
    assert_non_null(chain_set);
    assert_string_equal(chain_set->name, "nets");
    assert_true(chain_set->use_trie);
    assert_int_equal(bf_list_size(&chain_set->elems), 3);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(dump),
        cmocka_unit_test(get_set_from_matcher),
        cmocka_unit_test(update_set),
        cmocka_unit_test(update_set_not_found),
        cmocka_unit_test(update_set_key_mismatch),
        cmocka_unit_test(update_set_trie),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
