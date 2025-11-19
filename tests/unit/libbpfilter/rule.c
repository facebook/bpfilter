/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/rule.h>

#include "bpfilter/list.h"
#include "bpfilter/pack.h"
#include "bpfilter/runtime.h"
#include "fake.h"
#include "test.h"

static void to_from_str(void **state)
{
    (void)state;

    assert_enum_to_from_str(enum bf_pkthdr, bf_pkthdr_to_str,
                            bf_pkthdr_from_str, BF_PKTHDR_LINK, _BF_PKTHDR_MAX);
}

static void new_and_free(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    // Free rule manually
    assert_ok(bf_rule_new(&rule));
    bf_rule_free(&rule);
    assert_null(rule);

    // Free rule using the cleanup attribute
    assert_ok(bf_rule_new(&rule));
}

static void pack_and_unpack(void **state)
{
    _free_bf_rule_ struct bf_rule *source = NULL;
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Pack the source rule
    assert_non_null(source = bft_rule_dummy(8));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "rule");
    assert_ok(bf_rule_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack in the destination counter
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "rule", &node));
    assert_ok(bf_rule_new_from_pack(&destination, node));

    assert_true(bft_rule_equal(source, destination));
}

static void unpack_error(void **state)
{
    _free_bf_rule_ struct bf_rule *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_u32(wpack, "index", 8);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_err(bf_rule_new_from_pack(&destination, bf_rpack_root(rpack)));
}

static void dump(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;

    (void)state;

    assert_non_null(rule = bft_rule_dummy(8));

    // Dump a list with matchers
    bf_rule_dump(rule, EMPTY_PREFIX);

    // Dump a list without matchers
    bf_list_clean(&rule->matchers);
    bf_rule_dump(rule, EMPTY_PREFIX);
}

static void add_matcher(void **state)
{
    _free_bf_rule_ struct bf_rule *rule = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher0 = NULL;
    _free_bf_matcher_ struct bf_matcher *matcher1 = NULL;
    (void)state;

    assert_non_null(rule = bft_rule_dummy(0));

    assert_non_null(matcher0 = bft_matcher_dummy("hello", 6));
    assert_ok(bf_rule_add_matcher(
        rule, bf_matcher_get_type(matcher0), bf_matcher_get_op(matcher0),
        bf_matcher_payload(matcher0), bf_matcher_payload_len(matcher0)));
    assert_int_equal(bf_list_size(&rule->matchers), 1);
    assert_true(bft_matcher_equal(
        matcher0, bf_list_node_get_data(bf_list_get_tail(&rule->matchers))));

    assert_non_null(matcher1 = bft_matcher_dummy("", 1));
    assert_ok(bf_rule_add_matcher(
        rule, bf_matcher_get_type(matcher1), bf_matcher_get_op(matcher1),
        bf_matcher_payload(matcher1), bf_matcher_payload_len(matcher1)));
    assert_int_equal(bf_list_size(&rule->matchers), 2);
    assert_true(bft_matcher_equal(
        matcher1, bf_list_node_get_data(bf_list_get_tail(&rule->matchers))));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_from_str),
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(unpack_error),
        cmocka_unit_test(dump),
        cmocka_unit_test(add_matcher),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
