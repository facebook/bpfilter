/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/target.c"

#include <criterion/criterion.h>

#include "test.h"

TestAssert(src_core_target, bf_target_type_to_str, (-1));
TestAssert(src_core_target, bf_target_type_to_str, (_BF_TARGET_TYPE_MAX));
TestAssert(src_core_target, bf_target_standard_verdict_to_str, (-1));
TestAssert(src_core_target, bf_target_standard_verdict_to_str,
           (_BF_TARGET_STANDARD_MAX));
TestAssert(src_core_target, bf_target_ops_get, (-1));
TestAssert(src_core_target, bf_target_ops_get, (_BF_TARGET_TYPE_MAX));

Test(src_core_target, can_get_target_type_str)
{
    for (int i = 0; i < _BF_TARGET_TYPE_MAX; ++i)
        cr_assert_not_null(bf_target_type_to_str(i));
}

Test(src_core_target, can_get_std_verdict_to_str)
{
    for (int i = 0; i < _BF_TARGET_STANDARD_MAX; ++i)
        cr_assert_not_null(bf_target_standard_verdict_to_str(i));
}

Test(src_core_target, can_get_target_ops)
{
    for (int i = 0; i < _BF_TARGET_TYPE_MAX; ++i)
        cr_assert_not_null(bf_target_ops_get(i));
}
