/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/rule.c"

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

Test(rule, marsh_unmarsh)
{
    expect_assert_failure(bf_rule_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_rule_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_rule_unmarsh(NULL, NOT_NULL));
    expect_assert_failure(bf_rule_unmarsh(NOT_NULL, NULL));

    // All good
    {
        _free_bf_rule_ struct bf_rule *rule0 = bf_test_get_rule(10);
        _free_bf_rule_ struct bf_rule *rule1 = NULL;
        _free_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_non_null(rule0);
        assert_int_equal(0, bf_rule_marsh(rule0, &marsh));
        assert_int_equal(0, bf_rule_unmarsh(marsh, &rule1));

        assert_int_equal(rule0->index, rule1->index);
        assert_int_equal(bf_list_size(&rule0->matchers),
                         bf_list_size(&rule1->matchers));
        assert_int_equal(rule0->counters, rule1->counters);
        assert_int_equal(rule0->verdict, rule1->verdict);
    }

    // Failed serialisation
    {
        _free_bf_rule_ struct bf_rule *rule = bf_test_get_rule(10);
        _free_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_non_null(rule);

        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);
        assert_error(bf_rule_marsh(rule, &marsh));
    }
}
