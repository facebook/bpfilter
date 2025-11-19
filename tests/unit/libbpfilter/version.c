/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/version.h>

#include "test.h"

static void get_version(void **state)
{
    (void)state;

    assert_non_null(bf_version());
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(get_version),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
