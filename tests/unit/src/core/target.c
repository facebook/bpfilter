/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/target.c"

#include "harness/cmocka.h"
#include "harness/mock.h"

Test(target, target_type_to_str_assert_failure)
{
    expect_assert_failure(bf_target_type_to_str(-1));
    expect_assert_failure(bf_target_type_to_str(_BF_TARGET_TYPE_MAX));
}

Test(target, can_get_target_type_str)
{
    for (int i = 0; i < _BF_TARGET_TYPE_MAX; ++i)
        assert_true(bf_target_type_to_str(i));
}

Test(target, standard_verdict_to_str_assert_failure)
{
    expect_assert_failure(bf_target_standard_verdict_to_str(-1));
    expect_assert_failure(
        bf_target_standard_verdict_to_str(_BF_TARGET_STANDARD_MAX));
}

Test(target, can_get_standard_verdict_str)
{
    for (int i = 0; i < _BF_TARGET_STANDARD_MAX; ++i)
        assert_true(bf_target_standard_verdict_to_str(i));
}

Test(target, target_ops_get_assert_failure)
{
    expect_assert_failure(bf_target_ops_get(-1));
    expect_assert_failure(bf_target_ops_get(_BF_TARGET_TYPE_MAX));
}

Test(target, can_get_target_ops)
{
    for (int i = 0; i < _BF_TARGET_TYPE_MAX; ++i)
        assert_true(bf_target_ops_get(i));
}

Test(target, generate_error_is_not_supported)
{
    assert_int_equal(bf_target_generate_error(NULL, NULL), -ENOTSUP);
}

Test(target, new_failure)
{
    expect_assert_failure(bf_target_new(NULL));

    {
        struct bf_target *target = NOT_NULL;
        _cleanup_bf_mock_ bf_mock _ = bf_mock_get(calloc, NULL);

        assert_true(bf_target_new(&target) < 0);
        assert_int_equal(target, NOT_NULL);
    }
}

Test(target, new)
{
    _cleanup_bf_target_ struct bf_target *target = NULL;

    assert_int_equal(bf_target_new(&target), 0);
    bf_target_free(&target);
    assert_null(target);
}
