/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <arpa/inet.h>

#include <bpfilter/hashset.h>

#include "bpfilter/dump.h"
#include "bpfilter/pack.h"
#include "fake.h"
#include "test.h"

static void new_and_free(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    // Free set manually
    assert_ok(bf_hashset_new(&set, "test_set", key, ARRAY_SIZE(key)));
    assert_non_null(set);
    assert_string_equal(set->name, "test_set");
    assert_int_equal(set->n_comps, 1);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_SADDR);
    bf_hashset_free(&set);
    assert_null(set);

    // Free set using the cleanup attribute
    assert_ok(bf_hashset_new(&set, NULL, key, ARRAY_SIZE(key)));
    assert_null(set->name);
}

static void new_with_multiple_keys(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_hashset_new(&set, "multi_key_set", key, ARRAY_SIZE(key)));
    assert_non_null(set);
    assert_int_equal(set->n_comps, 2);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_DADDR);
    assert_int_equal(set->key[1], BF_MATCHER_TCP_SPORT);
}

static void new_with_invalid_params(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    // Test with 0 components
    assert_err(bf_hashset_new(&set, "test", key, 0));

    // Test with too many components
    enum bf_matcher_type large_key[BF_HASHSET_MAX_N_COMPS + 1];
    for (size_t i = 0; i <= BF_HASHSET_MAX_N_COMPS; ++i)
        large_key[i] = BF_MATCHER_IP4_SADDR;
    assert_err(
        bf_hashset_new(&set, "test", large_key, BF_HASHSET_MAX_N_COMPS + 1));
}

static void new_with_trie_key(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SNET};

    (void)state;

    // Network matchers should enable trie
    assert_ok(bf_hashset_new(&set, "trie_set", key, ARRAY_SIZE(key)));
    assert_true(set->use_trie);
}

static void new_with_invalid_network_combination(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SNET, BF_MATCHER_TCP_SPORT};

    (void)state;

    // Network matchers can't be combined with other matchers
    assert_err(bf_hashset_new(&set, "invalid_set", key, ARRAY_SIZE(key)));
}

static void add_elem(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem = 0x01020304; // 1.2.3.4

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_hashset_add_elem(set, &elem));
    assert_int_equal(bf_hashset_size(set), 1);
}

static void add_multiple_elems(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_DADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    // Add 5 elements
    for (size_t i = 0; i < 5; ++i) {
        uint8_t elem[set->elem_size];
        memset(elem, (uint8_t)i, set->elem_size);
        assert_ok(bf_hashset_add_elem(set, elem));
    }

    assert_int_equal(bf_hashset_size(set), 5);
}

static void pack_and_unpack(void **state)
{
    _free_bf_hashset_ struct bf_hashset *source = NULL;
    _free_bf_hashset_ struct bf_hashset *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Create and pack the source set
    assert_non_null(source = bft_hashset_dummy(4));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "set");
    assert_ok(bf_hashset_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination set
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &node));
    assert_ok(bf_hashset_new_from_pack(&destination, node));

    assert_true(bft_hashset_eq(source, destination));
}

static void pack_and_unpack_empty(void **state)
{
    _free_bf_hashset_ struct bf_hashset *source = NULL;
    _free_bf_hashset_ struct bf_hashset *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    // Create empty set and pack it
    assert_ok(bf_hashset_new(&source, "empty_set", key, ARRAY_SIZE(key)));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "set");
    assert_ok(bf_hashset_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack into destination
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "set", &node));
    assert_ok(bf_hashset_new_from_pack(&destination, node));

    assert_true(bft_hashset_eq(source, destination));
    assert_int_equal(bf_hashset_size(destination), 0);
}

static void dump(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;
    prefix_t prefix = {};

    (void)state;

    // Dump a set with elements
    assert_non_null(set = bft_hashset_dummy(4));
    bf_hashset_dump(set, &prefix);
}

static void dump_empty(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    prefix_t prefix = {};

    (void)state;

    // Dump an empty set
    assert_ok(bf_hashset_new(&set, "empty", key, ARRAY_SIZE(key)));
    bf_hashset_dump(set, &prefix);
}

static void new_from_raw(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    (void)state;

    // Test creating set from raw key and payload
    assert_ok(bf_hashset_new_from_raw(&set, "test_raw", "(ip4.saddr)",
                                      "{1.2.3.4; 5.6.7.8}"));
    assert_non_null(set);
    assert_string_equal(set->name, "test_raw");
    assert_int_equal(set->n_comps, 1);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_SADDR);
    assert_int_equal(bf_hashset_size(set), 2);
}

static void new_from_raw_multiple_keys(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    (void)state;

    // Test creating set with multiple key components
    assert_ok(bf_hashset_new_from_raw(&set, "test_multi",
                                      "(ip4.daddr, tcp.sport)",
                                      "{1.2.3.4, 80; 5.6.7.8, 443}"));
    assert_non_null(set);
    assert_int_equal(set->n_comps, 2);
    assert_int_equal(set->key[0], BF_MATCHER_IP4_DADDR);
    assert_int_equal(set->key[1], BF_MATCHER_TCP_SPORT);
    assert_int_equal(bf_hashset_size(set), 2);
}

static void new_from_raw_invalid(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    (void)state;

    // Test with invalid key format
    assert_err(bf_hashset_new_from_raw(&set, "test", "INVALID", "{1.2.3.4}"));

    // Test with empty key
    assert_err(bf_hashset_new_from_raw(&set, "test", "()", "{1.2.3.4}"));
}

static void add_many_basic(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_add = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key, ARRAY_SIZE(key)));
    assert_ok(bf_hashset_new(&to_add, "to_add", key, ARRAY_SIZE(key)));

    assert_ok(bf_hashset_add_elem(dest, &elem1));
    assert_ok(bf_hashset_add_elem(dest, &elem2));

    assert_ok(bf_hashset_add_elem(to_add, &elem2));
    assert_ok(bf_hashset_add_elem(to_add, &elem3));

    assert_ok(bf_hashset_add_many(dest, &to_add));

    assert_int_equal(bf_hashset_size(dest), 3);
    assert_true(bf_hashset_contains(dest, &elem1));
    assert_true(bf_hashset_contains(dest, &elem2));
    assert_true(bf_hashset_contains(dest, &elem3));
    assert_null(to_add);
}

static void add_many_mismatched_key_count(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_add = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_SADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_hashset_new(&to_add, "to_add", key2, ARRAY_SIZE(key2)));

    assert_err(bf_hashset_add_many(dest, &to_add));
    assert_non_null(to_add);
}

static void add_many_mismatched_key_type(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_add = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_DADDR};

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_hashset_new(&to_add, "to_add", key2, ARRAY_SIZE(key2)));

    assert_err(bf_hashset_add_many(dest, &to_add));
    assert_non_null(to_add);
}

static void remove_many_basic(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_remove = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key, ARRAY_SIZE(key)));
    assert_ok(bf_hashset_new(&to_remove, "to_remove", key, ARRAY_SIZE(key)));

    assert_ok(bf_hashset_add_elem(dest, &elem1));
    assert_ok(bf_hashset_add_elem(dest, &elem2));
    assert_ok(bf_hashset_add_elem(dest, &elem3));

    assert_ok(bf_hashset_add_elem(to_remove, &elem2));

    assert_ok(bf_hashset_remove_many(dest, &to_remove));

    assert_int_equal(bf_hashset_size(dest), 2);
    assert_true(bf_hashset_contains(dest, &elem1));
    assert_false(bf_hashset_contains(dest, &elem2));
    assert_true(bf_hashset_contains(dest, &elem3));
    assert_null(to_remove);
}

static void remove_many_disjoint_sets(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_remove = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t elem3 = 0x03030303;
    uint32_t elem4 = 0x04040404;

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key, ARRAY_SIZE(key)));
    assert_ok(bf_hashset_new(&to_remove, "to_remove", key, ARRAY_SIZE(key)));

    assert_ok(bf_hashset_add_elem(dest, &elem1));
    assert_ok(bf_hashset_add_elem(dest, &elem2));

    assert_ok(bf_hashset_add_elem(to_remove, &elem3));
    assert_ok(bf_hashset_add_elem(to_remove, &elem4));

    assert_ok(bf_hashset_remove_many(dest, &to_remove));
    assert_int_equal(bf_hashset_size(dest), 2);
    assert_true(bf_hashset_contains(dest, &elem1));
    assert_true(bf_hashset_contains(dest, &elem2));
    assert_null(to_remove);
}

static void contains(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t missing = 0x09090909;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    assert_false(bf_hashset_contains(set, &elem1));

    assert_ok(bf_hashset_add_elem(set, &elem1));
    assert_ok(bf_hashset_add_elem(set, &elem2));

    assert_true(bf_hashset_contains(set, &elem1));
    assert_true(bf_hashset_contains(set, &elem2));
    assert_false(bf_hashset_contains(set, &missing));
}

static void remove_elem(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem1 = 0x01010101;
    uint32_t elem2 = 0x02020202;
    uint32_t missing = 0x09090909;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_hashset_add_elem(set, &elem1));
    assert_ok(bf_hashset_add_elem(set, &elem2));
    assert_int_equal(bf_hashset_size(set), 2);

    // Remove existing element
    assert_ok(bf_hashset_remove(set, &elem1));
    assert_int_equal(bf_hashset_size(set), 1);
    assert_false(bf_hashset_contains(set, &elem1));
    assert_true(bf_hashset_contains(set, &elem2));

    // Remove nonexistent element is a no-op
    assert_ok(bf_hashset_remove(set, &missing));
    assert_int_equal(bf_hashset_size(set), 1);

    // Re-add after removal (tombstone reuse)
    assert_ok(bf_hashset_add_elem(set, &elem1));
    assert_int_equal(bf_hashset_size(set), 2);
    assert_true(bf_hashset_contains(set, &elem1));
}

static void is_empty_and_cap(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem = 0x01010101;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    assert_true(bf_hashset_is_empty(set));
    assert_int_equal(bf_hashset_cap(set), 0);

    assert_ok(bf_hashset_add_elem(set, &elem));

    assert_false(bf_hashset_is_empty(set));
    assert_true(bf_hashset_cap(set) > 0);
}

static void foreach_basic(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elems[] = {0x01010101, 0x02020202, 0x03030303};
    size_t count;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    // foreach on empty set does nothing
    count = 0;
    bf_hashset_foreach (set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 0);

    for (size_t i = 0; i < ARRAY_SIZE(elems); ++i)
        assert_ok(bf_hashset_add_elem(set, &elems[i]));

    // foreach visits every element
    count = 0;
    bf_hashset_foreach (set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 3);
}

static void foreach_after_removal(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elems[] = {0x01010101, 0x02020202, 0x03030303};
    size_t count;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    for (size_t i = 0; i < ARRAY_SIZE(elems); ++i)
        assert_ok(bf_hashset_add_elem(set, &elems[i]));

    assert_ok(bf_hashset_remove(set, &elems[1]));

    // Tombstoned slot must be skipped
    count = 0;
    bf_hashset_foreach (set, elem) {
        (void)elem;
        ++count;
    }
    assert_int_equal(count, 2);
}

static void add_triggers_grow(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    for (uint32_t i = 0; i < 20; ++i) {
        uint32_t addr = htonl(0x0a000001 + i);
        assert_ok(bf_hashset_add_elem(set, &addr));
    }

    assert_int_equal(bf_hashset_size(set), 20);
    assert_true(bf_hashset_cap(set) > 16);

    for (uint32_t i = 0; i < 20; ++i) {
        uint32_t addr = htonl(0x0a000001 + i);
        assert_true(bf_hashset_contains(set, &addr));
    }
}

static void foreach_break(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elems[] = {0x01010101, 0x02020202, 0x03030303};
    size_t count;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));

    for (size_t i = 0; i < ARRAY_SIZE(elems); ++i)
        assert_ok(bf_hashset_add_elem(set, &elems[i]));

    count = 0;
    bf_hashset_foreach (set, elem) {
        (void)elem;
        ++count;
        break;
    }
    assert_int_equal(count, 1);
}

static void add_duplicate(void **state)
{
    _free_bf_hashset_ struct bf_hashset *set = NULL;

    enum bf_matcher_type key[] = {BF_MATCHER_IP4_SADDR};

    uint32_t elem = 0x01010101;

    (void)state;

    assert_ok(bf_hashset_new(&set, "test", key, ARRAY_SIZE(key)));
    assert_ok(bf_hashset_add_elem(set, &elem));
    assert_ok(bf_hashset_add_elem(set, &elem));
    assert_int_equal(bf_hashset_size(set), 1);
}

static void remove_many_mismatched_key_count(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_remove = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_SADDR, BF_MATCHER_TCP_SPORT};

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_hashset_new(&to_remove, "to_remove", key2, ARRAY_SIZE(key2)));

    assert_err(bf_hashset_remove_many(dest, &to_remove));
    assert_non_null(to_remove);
}

static void remove_many_mismatched_key_type(void **state)
{
    _free_bf_hashset_ struct bf_hashset *dest = NULL;
    _free_bf_hashset_ struct bf_hashset *to_remove = NULL;

    enum bf_matcher_type key1[] = {BF_MATCHER_IP4_SADDR};

    enum bf_matcher_type key2[] = {BF_MATCHER_IP4_DADDR};

    (void)state;

    assert_ok(bf_hashset_new(&dest, "dest", key1, ARRAY_SIZE(key1)));
    assert_ok(bf_hashset_new(&to_remove, "to_remove", key2, ARRAY_SIZE(key2)));

    assert_err(bf_hashset_remove_many(dest, &to_remove));
    assert_non_null(to_remove);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(new_with_multiple_keys),
        cmocka_unit_test(new_with_invalid_params),
        cmocka_unit_test(new_with_trie_key),
        cmocka_unit_test(new_with_invalid_network_combination),
        cmocka_unit_test(add_elem),
        cmocka_unit_test(add_multiple_elems),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(pack_and_unpack_empty),
        cmocka_unit_test(dump),
        cmocka_unit_test(dump_empty),
        cmocka_unit_test(new_from_raw),
        cmocka_unit_test(new_from_raw_multiple_keys),
        cmocka_unit_test(new_from_raw_invalid),
        cmocka_unit_test(contains),
        cmocka_unit_test(remove_elem),
        cmocka_unit_test(is_empty_and_cap),
        cmocka_unit_test(foreach_basic),
        cmocka_unit_test(foreach_after_removal),
        cmocka_unit_test(add_triggers_grow),
        cmocka_unit_test(foreach_break),
        cmocka_unit_test(add_duplicate),
        cmocka_unit_test(add_many_basic),
        cmocka_unit_test(add_many_mismatched_key_count),
        cmocka_unit_test(add_many_mismatched_key_type),
        cmocka_unit_test(remove_many_basic),
        cmocka_unit_test(remove_many_disjoint_sets),
        cmocka_unit_test(remove_many_mismatched_key_count),
        cmocka_unit_test(remove_many_mismatched_key_type),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
