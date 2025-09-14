/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/verdict.c"

#include "harness/test.h"
#include "mock.h"

Test(verdict, verdict_to_str_to_verdict)
{
    enum bf_verdict verdict;

    expect_assert_failure(bf_verdict_to_str(-1));
    expect_assert_failure(bf_verdict_to_str(_BF_VERDICT_MAX));
    expect_assert_failure(bf_verdict_from_str(NULL, NOT_NULL));
    expect_assert_failure(bf_verdict_from_str(NOT_NULL, NULL));

    for (int i = 0; i < _BF_VERDICT_MAX; ++i) {
        const char *str = bf_verdict_to_str(i);

        assert_non_null(str);
        assert_int_not_equal(-1, bf_verdict_from_str(str, &verdict));
        assert_int_equal(verdict, i);
    }

    assert_int_not_equal(0, bf_verdict_from_str("", &verdict));
    assert_int_not_equal(0, bf_verdict_from_str("invalid", &verdict));
}
