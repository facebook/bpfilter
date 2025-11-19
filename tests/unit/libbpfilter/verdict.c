/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/verdict.h>

#include "test.h"

static void to_from_str(void **state)
{
    (void)state;

    assert_enum_to_from_str(enum bf_verdict, bf_verdict_to_str,
                            bf_verdict_from_str, BF_VERDICT_ACCEPT,
                            _BF_VERDICT_MAX);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_from_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
