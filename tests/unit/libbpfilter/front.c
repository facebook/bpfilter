/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/front.c"

#include "harness/test.h"
#include "mock.h"

Test(shared_front, front_to_str_assert_failure)
{
    expect_assert_failure(bf_front_to_str(-1));
    expect_assert_failure(bf_front_to_str(_BF_FRONT_MAX));
}

Test(hook, can_get_str_from_front)
{
    for (int i = 0; i < _BF_FRONT_MAX; ++i)
        assert_non_null(bf_front_to_str(i));
}
