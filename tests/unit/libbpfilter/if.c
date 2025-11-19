/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/if.h"

#include <limits.h>

#include "fake.h"
#include "test.h"

static void name_and_index(void **state)
{
    const char *name;
    int ifindex;

    (void)state;

    assert_err(bf_if_index_from_name("invalid iface name"));
    assert_int_gte(ifindex = bf_if_index_from_name("lo"), 0);

    assert_null(bf_if_name_from_index(INT_MAX));
    assert_non_null(name = bf_if_name_from_index(ifindex));
    assert_string_equal(name, "lo");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(name_and_index),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
