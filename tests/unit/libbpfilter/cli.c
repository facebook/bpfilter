/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/counter.h>
#include <bpfilter/hook.h>
#include <bpfilter/list.h>

#include "fake.h"
#include "test.h"

static void ruleset_get(void **state)
{
    (void)state;

    _clean_bf_list_ bf_list chains =
        bf_list_default(bf_chain_free, bf_chain_pack);
    _clean_bf_list_ bf_list hookopts =
        bf_list_default(bf_hookopts_free, bf_hookopts_pack);
    _clean_bf_list_ bf_list counters =
        bf_list_default((bf_list_ops_free)bf_list_free, NULL);

    // Can't connect to daemon during unit tests
    assert_err(bf_ruleset_get(&chains, &hookopts, &counters));
}

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

    // Can't connect to daemon during unit tests
    assert_ok(bf_list_add_tail(&hookopts, NULL));
    assert_err(bf_ruleset_set(&chains, &hookopts));
}

static void ruleset_flush(void **state)
{
    (void)state;

    // Can't connect to daemon during unit tests
    assert_err(bf_ruleset_flush());
}

static void chain_set(void **state)
{
    (void)state;

    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(false);

    assert_non_null(chain);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_set(chain, NULL));
}

static void chain_get(void **state)
{
    (void)state;

    _free_bf_chain_ struct bf_chain *chain = NULL;
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _clean_bf_list_ bf_list counters =
        bf_list_default(bf_counter_free, bf_counter_pack);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_get("test_chain", &chain, &hookopts, &counters));
}

static void chain_prog_fd(void **state)
{
    (void)state;

    // NULL name should fail
    assert_int_equal(bf_chain_prog_fd(NULL), -EINVAL);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_prog_fd("test_chain"));
}

static void chain_logs_fd(void **state)
{
    (void)state;

    // NULL name should fail
    assert_int_equal(bf_chain_logs_fd(NULL), -EINVAL);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_logs_fd("test_chain"));
}

static void chain_load(void **state)
{
    (void)state;

    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(false);

    assert_non_null(chain);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_load(chain));
}

static void chain_attach(void **state)
{
    (void)state;

    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;

    assert_ok(bf_hookopts_new(&hookopts));
    assert_non_null(hookopts);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_attach("test_chain", hookopts));
}

static void chain_update(void **state)
{
    (void)state;

    _free_bf_chain_ struct bf_chain *chain = bft_chain_dummy(false);

    assert_non_null(chain);

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_update(chain));
}

static void chain_flush(void **state)
{
    (void)state;

    // Can't connect to daemon during unit tests
    assert_err(bf_chain_flush("test_chain"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(ruleset_get),   cmocka_unit_test(ruleset_set),
        cmocka_unit_test(ruleset_flush), cmocka_unit_test(chain_set),
        cmocka_unit_test(chain_get),     cmocka_unit_test(chain_prog_fd),
        cmocka_unit_test(chain_logs_fd), cmocka_unit_test(chain_load),
        cmocka_unit_test(chain_attach),  cmocka_unit_test(chain_update),
        cmocka_unit_test(chain_flush),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
