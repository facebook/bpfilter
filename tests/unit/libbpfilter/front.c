/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/front.h>

#include "test.h"

static void to_str(void **state)
{
    (void)state;

    assert_enum_to_str(enum bf_front, bf_front_to_str, BF_FRONT_IPT,
                       _BF_FRONT_MAX);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(to_str),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
