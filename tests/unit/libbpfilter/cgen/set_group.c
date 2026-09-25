/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#include "cgen/set_group.h"

#include <limits.h>
#include <stdint.h>

#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/matcher.h>
#include <bpfilter/pack.h>
#include <bpfilter/runtime.h>
#include <bpfilter/set.h>
#include <bpfilter/verdict.h>

#include "test.h"

static void _bft_push_set(bf_list *sets, enum bf_matcher_type type,
                          size_t min_size)
{
    _free_bf_set_ struct bf_set *set = NULL;

    assert_ok(bf_set_new(&set, NULL, &type, 1));
    set->min_size = min_size;
    assert_ok(bf_list_push(sets, (void **)&set));
}

/* Sets, in the chain's order:
 * - 0: ip4.saddr: group 0, bit 0
 * - 1: tcp.sport: group 1, bit 0
 * - 2: ip4.saddr, empty: no group
 * - 3: ip4.saddr: group 0, bit 1
 * - 4: ip4.snet (LPM trie): group 2, bit 0
 * - 5: ip4.snet (LPM trie): group 3, bit 0
 * - 6: ip4.saddr: group 0, bit 2
 * - 7: ip4.saddr, empty with a minimum size: group 0, bit 3
 * - 8: ip4.snet (LPM trie), empty with a minimum size: group 4, bit 0 */
static struct bf_chain *_bft_chain_with_sets(void)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, bf_set_pack);

    _bft_push_set(&sets, BF_MATCHER_IP4_SADDR, 0);
    _bft_push_set(&sets, BF_MATCHER_TCP_SPORT, 0);
    _bft_push_set(&sets, BF_MATCHER_IP4_SADDR, 0);
    _bft_push_set(&sets, BF_MATCHER_IP4_SADDR, 0);
    _bft_push_set(&sets, BF_MATCHER_IP4_SNET, 0);
    _bft_push_set(&sets, BF_MATCHER_IP4_SNET, 0);
    _bft_push_set(&sets, BF_MATCHER_IP4_SADDR, 0);
    _bft_push_set(&sets, BF_MATCHER_IP4_SADDR, 4);
    _bft_push_set(&sets, BF_MATCHER_IP4_SNET, 4);

    assert_ok(bf_chain_new(&chain, "test", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                           &sets, NULL));

    assert_ok(bf_set_add_elem(bf_list_get_at(&chain->sets, 0),
                              (uint8_t[4]) {10, 0, 0, 1}));
    assert_ok(bf_set_add_elem(bf_list_get_at(&chain->sets, 0),
                              (uint8_t[4]) {10, 0, 0, 2}));
    assert_ok(
        bf_set_add_elem(bf_list_get_at(&chain->sets, 1), (uint8_t[2]) {0, 80}));
    assert_ok(bf_set_add_elem(bf_list_get_at(&chain->sets, 3),
                              (uint8_t[4]) {10, 0, 0, 2}));
    assert_ok(bf_set_add_elem(bf_list_get_at(&chain->sets, 4),
                              &(struct bf_ip4_lpm_key) {.prefixlen = 24}));
    assert_ok(bf_set_add_elem(bf_list_get_at(&chain->sets, 5),
                              &(struct bf_ip4_lpm_key) {.prefixlen = 16}));
    assert_ok(bf_set_add_elem(bf_list_get_at(&chain->sets, 6),
                              (uint8_t[4]) {10, 0, 0, 1}));

    return TAKE_PTR(chain);
}

static void build_groups(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = _bft_chain_with_sets();
    _clean_bf_list_ bf_list groups = bf_list_default(NULL, NULL);
    const struct bf_set_group *group;

    // Expected group and bit index of each set, SIZE_MAX if not grouped.
    const size_t expected[][2] = {
        {0, 0}, {1, 0}, {SIZE_MAX, SIZE_MAX}, {0, 1}, {2, 0}, {3, 0}, {0, 2},
        {0, 3}, {4, 0},
    };

    (void)state;

    assert_ok(bf_set_group_build(&groups, chain));
    assert_int_equal(bf_list_size(&groups), 5);

    group = bf_list_get_at(&groups, 0);
    assert_int_equal(bf_list_size(&group->sets), 4);

    for (size_t i = 0; i < ARRAY_SIZE(expected); ++i) {
        const struct bf_set *set = bf_list_get_at(&chain->sets, i);
        size_t group_idx = SIZE_MAX;
        size_t bit_idx = SIZE_MAX;

        group = bf_set_group_find(&groups, set, &group_idx, &bit_idx);
        assert_int_equal(group_idx, expected[i][0]);
        assert_int_equal(bit_idx, expected[i][1]);

        if (expected[i][0] == SIZE_MAX)
            assert_null(group);
        else
            assert_ptr_equal(group, bf_list_get_at(&groups, group_idx));
    }

    // Output indexes are optional
    assert_non_null(bf_set_group_find(&groups, bf_list_get_at(&chain->sets, 6),
                                      NULL, NULL));
    assert_null(bf_set_group_find(&groups, NULL, NULL, NULL));
}

static void build_empty_chain(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = NULL;
    _clean_bf_list_ bf_list groups = bf_list_default(NULL, NULL);

    (void)state;

    assert_ok(bf_chain_new(&chain, "empty", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                           NULL, NULL));

    assert_ok(bf_set_group_build(&groups, chain));
    assert_true(bf_list_is_empty(&groups));
}

static void value_size(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = _bft_chain_with_sets();
    _free_bf_chain_ struct bf_chain *large = NULL;
    _clean_bf_list_ bf_list sets = bf_list_default(bf_set_free, bf_set_pack);
    _clean_bf_list_ bf_list groups = bf_list_default(NULL, NULL);
    _clean_bf_list_ bf_list large_groups = bf_list_default(NULL, NULL);

    (void)state;

    assert_ok(bf_set_group_build(&groups, chain));
    assert_int_equal(bf_set_group_value_size(bf_list_get_at(&groups, 0)), 1);

    // One bit per set: one set more than fits in a byte needs 2 bytes
    for (size_t i = 0; i < CHAR_BIT + 1; ++i)
        _bft_push_set(&sets, BF_MATCHER_IP4_SADDR, 0);

    assert_ok(bf_chain_new(&large, "large", BF_HOOK_XDP, BF_VERDICT_ACCEPT,
                           &sets, NULL));
    bf_list_foreach (&large->sets, set_node) {
        assert_ok(bf_set_add_elem(bf_list_node_get_data(set_node),
                                  (uint8_t[4]) {10, 0, 0, 1}));
    }
    assert_ok(bf_set_group_build(&large_groups, large));
    assert_int_equal(bf_list_size(&large_groups), 1);
    assert_int_equal(bf_set_group_value_size(bf_list_get_at(&large_groups, 0)),
                     2);
}

static void elem_value(void **state)
{
    _free_bf_chain_ struct bf_chain *chain = _bft_chain_with_sets();
    _clean_bf_list_ bf_list groups = bf_list_default(NULL, NULL);
    const struct bf_set_group *group;
    uint8_t value;

    (void)state;

    assert_ok(bf_set_group_build(&groups, chain));
    group = bf_list_get_at(&groups, 0);

    // In the group's 1st and 3rd sets: bits 0 and 2
    assert_true(
        bf_set_group_elem_value(group, (uint8_t[4]) {10, 0, 0, 1}, &value));
    assert_int_equal(value, 0x05);

    // In the group's 1st and 2nd sets: bits 0 and 1
    assert_true(
        bf_set_group_elem_value(group, (uint8_t[4]) {10, 0, 0, 2}, &value));
    assert_int_equal(value, 0x03);

    // In none of the group's sets: the value is cleared
    value = UINT8_MAX;
    assert_false(
        bf_set_group_elem_value(group, (uint8_t[4]) {10, 0, 0, 3}, &value));
    assert_int_equal(value, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(build_groups),
        cmocka_unit_test(build_empty_chain),
        cmocka_unit_test(value_size),
        cmocka_unit_test(elem_value),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
