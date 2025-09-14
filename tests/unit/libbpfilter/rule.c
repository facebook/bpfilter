/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/rule.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(rule, new_and_free)
{
    // Invalid argument
    expect_assert_failure(bf_rule_new(NULL));
    expect_assert_failure(bf_rule_free(NULL));

    // New, free, new again, then cleanup
    {
        _free_bf_rule_ struct bf_rule *rule = NULL;

        assert_success(bf_rule_new(&rule));
        bf_rule_free(&rule);
        assert_null(rule);
        bf_rule_free(&rule);

        assert_success(bf_rule_new(&rule));
    }

    // malloc failure
    {
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(calloc, NULL);
        struct bf_rule *rule;

        assert_error(bf_rule_new(&rule));
    }
}

Test(rule, pack_unpack)
{
    _free_bf_rule_ struct bf_rule *rule0 = NULL;
    _free_bf_rule_ struct bf_rule *rule1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    expect_assert_failure(bf_rule_pack(NULL, NOT_NULL));
    expect_assert_failure(bf_rule_pack(NOT_NULL, NULL));

    assert_non_null(rule0 = bf_test_get_rule(10));

    assert_success(bf_wpack_new(&wpack));
    assert_success(bf_rule_pack(rule0, wpack));
    assert_success(bf_wpack_get_data(wpack, &data, &data_len));

    assert_success(bf_rpack_new(&rpack, data, data_len));
    assert_success(bf_rule_new_from_pack(&rule1, bf_rpack_root(rpack)));

    assert_int_equal(rule0->index, rule1->index);
    assert_int_equal(bf_list_size(&rule0->matchers),
                        bf_list_size(&rule1->matchers));
    assert_int_equal(rule0->counters, rule1->counters);
    assert_int_equal(rule0->verdict, rule1->verdict);
}
