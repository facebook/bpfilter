/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/matcher.c"

#include "harness/test.h"
#include "mock.h"

Test(matcher, new_and_free)
{
    uint8_t payload[] = {0, 1, 2, 3, 4, 5, 6, 7};

    // Invalid argument
    expect_assert_failure(bf_matcher_new(NULL, 0, 0, NULL, 0));
    expect_assert_failure(bf_matcher_new(NOT_NULL, 0, 0, NULL, 1));
    expect_assert_failure(bf_matcher_free(NULL));

    // New, free, new again, then cleanup
    {
        _free_bf_matcher_ struct bf_matcher *matcher = NULL;

        assert_success(bf_matcher_new(&matcher, 0, 0, NULL, 0));
        bf_matcher_free(&matcher);
        assert_null(matcher);

        assert_int_equal(
            0, bf_matcher_new(&matcher, 0, 0, payload, sizeof(payload)));
    }

    // malloc failure
    {
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);
        struct bf_matcher *matcher;

        assert_error(bf_matcher_new(&matcher, 0, 0, NULL, 0));
    }

    // malloc failure with payload
    {
        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);
        struct bf_matcher *matcher;

        assert_int_not_equal(
            0, bf_matcher_new(&matcher, 0, 0, payload, sizeof(payload)));
    }
}

Test(matcher, marsh_unmarsh)
{
    uint8_t payload[] = {0, 1, 2, 3, 4, 5, 6, 7};

    expect_assert_failure(bf_matcher_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_matcher_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_matcher_new_from_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_matcher_new_from_marsh(NOT_NULL, NULL));

    // All good
    {
        _free_bf_matcher_ struct bf_matcher *matcher0 = NULL;
        _free_bf_matcher_ struct bf_matcher *matcher1 = NULL;
        _free_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_int_equal(
            0, bf_matcher_new(&matcher0, 1, 2, payload, sizeof(payload)));
        assert_success(bf_matcher_marsh(matcher0, &marsh));
        assert_success(bf_matcher_new_from_marsh(&matcher1, marsh));
    }

    // Failed serialisation
    {
        _free_bf_matcher_ struct bf_matcher *matcher0 = NULL;
        _free_bf_marsh_ struct bf_marsh *marsh = NULL;

        assert_int_equal(
            0, bf_matcher_new(&matcher0, 1, 2, payload, sizeof(payload)));

        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);
        assert_error(bf_matcher_marsh(matcher0, &marsh));
    }

    // Failed deserialisation
    {
        _free_bf_matcher_ struct bf_matcher *matcher0 = NULL;
        _free_bf_marsh_ struct bf_marsh *marsh = NULL;
        // No cleanup, it's not supposed to be allocated
        struct bf_matcher *matcher1 = NULL;

        assert_int_equal(
            0, bf_matcher_new(&matcher0, 1, 2, payload, sizeof(payload)));
        assert_success(bf_matcher_marsh(matcher0, &marsh));

        _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(malloc, NULL);
        assert_error(bf_matcher_new_from_marsh(&matcher1, marsh));
    }
}

Test(matcher, matcher_type_to_str_to_matcher_type)
{
    enum bf_matcher_type matcher_type;

    expect_assert_failure(bf_matcher_type_from_str(NULL, NOT_NULL));
    expect_assert_failure(bf_matcher_type_from_str(NOT_NULL, NULL));

    for (int i = 0; i < _BF_MATCHER_TYPE_MAX; ++i) {
        const char *str = bf_matcher_type_to_str(i);

        assert_non_null(str);
        assert_int_not_equal(-1, bf_matcher_type_from_str(str, &matcher_type));
        assert_int_equal(matcher_type, i);
    }

    assert_int_not_equal(0, bf_matcher_type_from_str("", &matcher_type));
    assert_int_not_equal(0, bf_matcher_type_from_str("invalid", &matcher_type));
}

Test(matcher, matcher_op_to_str_assert_failure)
{
    expect_assert_failure(bf_matcher_op_to_str(-1));
    expect_assert_failure(bf_matcher_op_to_str(_BF_MATCHER_OP_MAX));
}

Test(matcher, can_get_str_from_matcher_op)
{
    for (int i = 0; i < _BF_MATCHER_OP_MAX; ++i)
        assert_non_null(bf_matcher_op_to_str(i));
}
