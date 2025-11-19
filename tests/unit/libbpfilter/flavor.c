/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/flavor.h>

#include "test.h"

static void to_str(void **state)
{
    (void)state;

    assert_enum_to_str(enum bf_flavor, bf_flavor_to_str, BF_FLAVOR_TC,
                       _BF_FLAVOR_MAX);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
