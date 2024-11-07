/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/flavor.c"

#include "harness/test.h"
#include "harness/mock.h"

Test(flavor, flavor_to_str_assert_failure)
{
    expect_assert_failure(bf_flavor_to_str(-1));
    expect_assert_failure(bf_flavor_to_str(_BF_FLAVOR_MAX));
}

Test(flavor, can_get_flavor_str)
{
    for (int i = 0; i < _BF_FLAVOR_MAX; ++i)
        assert_non_null(bf_flavor_to_str(i));
}
