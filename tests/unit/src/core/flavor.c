/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/flavor.c"

#include <criterion/criterion.h>

#include "test.h"

TestAssert(src_core_flavor, bf_flavor_ops_get, 0, (-1));
TestAssert(src_core_flavor, bf_flavor_ops_get, 1, (_BF_FLAVOR_MAX));
TestAssert(src_core_flavor, bf_flavor_to_str, 0, (-1));
TestAssert(src_core_flavor, bf_flavor_to_str, 1, (_BF_FLAVOR_MAX));

Test(src_core_flavor, can_get_flavor_ops)
{
    for (int i = 0; i < _BF_FLAVOR_MAX; ++i)
        cr_assert_not_null(bf_flavor_ops_get(i));
}

Test(src_core_flavor, can_get_flavor_str)
{
    for (int i = 0; i < _BF_FLAVOR_MAX; ++i)
        cr_assert_not_null(bf_flavor_to_str(i));
}
