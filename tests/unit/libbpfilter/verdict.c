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

static void redirect_dir_to_from_str(void **state)
{
    (void)state;

    assert_enum_to_from_str(enum bf_redirect_dir, bf_redirect_dir_to_str,
                            bf_redirect_dir_from_str, BF_REDIRECT_INGRESS,
                            _BF_REDIRECT_DIR_MAX);

    // Verify specific direction strings
    assert_string_equal(bf_redirect_dir_to_str(BF_REDIRECT_INGRESS), "in");
    assert_string_equal(bf_redirect_dir_to_str(BF_REDIRECT_EGRESS), "out");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_from_str),
        cmocka_unit_test(redirect_dir_to_from_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
