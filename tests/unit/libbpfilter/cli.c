/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/core/list.h>
#include <bpfilter/counter.h>
#include <bpfilter/hook.h>

#include "fake.h"
#include "test.h"

static void ruleset_set(void **state)
{
    (void)state;

    _clean_bf_list_ bf_list chains =
        bf_list_default(bf_chain_free, bf_chain_pack);
    _clean_bf_list_ bf_list hookopts =
        bf_list_default(bf_hookopts_free, bf_hookopts_pack);

    // Mismatched list sizes should fail
    assert_ok(bf_list_add_tail(&chains, bft_chain_dummy(false)));
    assert_int_equal(bf_ruleset_set(&chains, &hookopts), -EINVAL);
}

static void chain_prog_fd(void **state)
{
    (void)state;

    // NULL name should fail
    assert_int_equal(bf_chain_prog_fd(NULL), -EINVAL);
}

static void chain_logs_fd(void **state)
{
    (void)state;

    // NULL name should fail
    assert_int_equal(bf_chain_logs_fd(NULL), -EINVAL);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ruleset_set),
        cmocka_unit_test(chain_prog_fd),
        cmocka_unit_test(chain_logs_fd),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
