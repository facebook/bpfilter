/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/verdict.c"

#include "harness/cmocka.h"
#include "harness/mock.h"

Test(verdict, bf_verdict_to_str)
{
    expect_assert_failure(bf_verdict_to_str(-1));

    for (int i = 0; i < _BF_VERDICT_MAX; ++i)
        assert_true(bf_verdict_to_str(i));

    expect_assert_failure(bf_verdict_to_str(_BF_VERDICT_MAX));
}
