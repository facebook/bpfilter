/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpfilter/ns.h>

#include "bpfilter/io.h"
#include "fake.h"
#include "mock.h"
#include "test.h"

static void init_and_clean(void **state)
{
    _clean_bf_ns_ struct bf_ns ns = bf_ns_default();

    (void)state;

    bf_ns_clean(&ns);
    ns = bf_ns_default();

    assert_ok(bf_ns_init(&ns, getpid()));
    bf_ns_clean(&ns);

    assert_ok(bf_ns_init(&ns, getpid()));
}

static void change_ns_same(void **state)
{
    _clean_bf_ns_ struct bf_ns ns = bf_ns_default();

    (void)state;

    // Mock setns to avoid permission errors
    _clean_bft_mock_ bft_mock mock = bft_mock_get(setns);
    (void)mock;

    assert_ok(bf_ns_init(&ns, getpid()));
    // Setting to same namespace should succeed (no actual setns calls needed
    // when inodes match)
    assert_ok(bf_ns_set(&ns, &ns));
}

static void change_ns_different(void **state)
{
    _clean_bf_ns_ struct bf_ns ns = bf_ns_default();
    struct bf_ns oldns = bf_ns_default();

    (void)state;

    // Mock setns to avoid permission errors
    _clean_bft_mock_ bft_mock mock = bft_mock_get(setns);
    (void)mock;

    assert_ok(bf_ns_init(&ns, getpid()));

    // Set oldns to different inodes to force setns calls
    oldns.net.inode = 0;
    oldns.mnt.inode = 0;

    assert_ok(bf_ns_set(&ns, &oldns));
}

static void change_ns_no_oldns(void **state)
{
    _clean_bf_ns_ struct bf_ns ns = bf_ns_default();

    (void)state;

    // Mock setns to avoid permission errors
    _clean_bft_mock_ bft_mock mock = bft_mock_get(setns);
    (void)mock;

    assert_ok(bf_ns_init(&ns, getpid()));

    // NULL oldns should force setns calls for both namespaces
    assert_ok(bf_ns_set(&ns, NULL));
}

static void init_invalid_pid(void **state)
{
    _clean_bf_ns_ struct bf_ns ns = bf_ns_default();

    (void)state;

    // Invalid PID should fail
    assert_err(bf_ns_init(&ns, -1));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(change_ns_same),
        cmocka_unit_test(change_ns_different),
        cmocka_unit_test(change_ns_no_oldns),
        cmocka_unit_test(init_invalid_pid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
