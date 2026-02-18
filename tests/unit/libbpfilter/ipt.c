/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>

#include <string.h>

#include <bpfilter/bpfilter.h>

#include "fake.h"
#include "test.h"

static void ipt_replace(void **state)
{
    (void)state;

    struct ipt_replace replace = {0};

    strncpy(replace.name, "filter", sizeof(replace.name) - 1);

    // Can't connect to daemon during unit tests
    assert_err(bf_ipt_replace(&replace));
}

static void ipt_add_counters(void **state)
{
    (void)state;

    struct xt_counters_info counters = {0};

    strncpy(counters.name, "filter", sizeof(counters.name) - 1);

    // Can't connect to daemon during unit tests
    assert_err(bf_ipt_add_counters(&counters));
}

static void ipt_get_info(void **state)
{
    (void)state;

    struct ipt_getinfo info = {0};

    strncpy(info.name, "filter", sizeof(info.name) - 1);

    // Can't connect to daemon during unit tests
    assert_err(bf_ipt_get_info(&info));
}

static void ipt_get_entries(void **state)
{
    (void)state;

    struct ipt_get_entries entries = {0};

    strncpy(entries.name, "filter", sizeof(entries.name) - 1);

    // Can't connect to daemon during unit tests
    assert_err(bf_ipt_get_entries(&entries));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ipt_replace),
        cmocka_unit_test(ipt_add_counters),
        cmocka_unit_test(ipt_get_info),
        cmocka_unit_test(ipt_get_entries),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
