/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/rule.c"

#include "harness/cmocka.h"
#include "harness/mock.h"

static int _create_dummy_rule(struct bf_rule **rule)
{
    struct bf_rule *_rule;
    int r;

    bf_assert(rule);

    r = bf_rule_new(rule);
    if (r)
        return r;

    _rule = *rule;
    _rule->index = 1;
    _rule->ifindex = 2;

    for (int i = 0; i < 10; ++i) {
        _cleanup_bf_matcher_ struct bf_matcher *matcher = NULL;

        r = bf_matcher_new(&matcher, 0, 0, (void *)&i, sizeof(i));
        if (r)
            return r;

        r = bf_list_add_tail(&_rule->matchers, matcher);
        if (r)
            return r;

        TAKE_PTR(matcher);
    }

    _rule->counters = true;
    _rule->verdict = 1;

    return 0;
}

Test(rule, new_and_free)
{
    // Invalid argument
    expect_assert_failure(bf_rule_new(NULL));
    expect_assert_failure(bf_rule_free(NULL));

    // New, free, new again, then cleanup
    {
        _cleanup_bf_rule_ struct bf_rule *rule = NULL;

        assert_int_equal(0, bf_rule_new(&rule));
        bf_rule_free(&rule);
        assert_null(rule);
        bf_rule_free(&rule);

        assert_int_equal(0, bf_rule_new(&rule));
    }

    // malloc failure
    {
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);
        struct bf_rule *rule;

        assert_int_not_equal(0, bf_rule_new(&rule));
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
        _cleanup_bf_rule_ struct bf_rule *rule0 = NULL;
        _cleanup_bf_rule_ struct bf_rule *rule1 = NULL;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_int_equal(0, _create_dummy_rule(&rule0));
        assert_int_equal(0, bf_rule_marsh(rule0, &marsh));
        assert_int_equal(0, bf_rule_unmarsh(marsh, &rule1));

        assert_int_equal(rule0->index, rule1->index);
        assert_int_equal(rule0->ifindex, rule1->ifindex);
        assert_int_equal(bf_list_size(&rule0->matchers),
                         bf_list_size(&rule1->matchers));
        assert_int_equal(rule0->counters, rule1->counters);
        assert_int_equal(rule0->verdict, rule1->verdict);
    }

    // Failed serialisation
    {
        _cleanup_bf_rule_ struct bf_rule *rule = NULL;
        _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_int_equal(0, _create_dummy_rule(&rule));

        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(malloc, NULL);
        assert_int_not_equal(0, bf_rule_marsh(rule, &marsh));
    }
}
