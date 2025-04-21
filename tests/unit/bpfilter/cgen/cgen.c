/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/cgen.c"

#include "fake.h"
#include "harness/test.h"
#include "mock.h"

Test(cgen, create_delete_assert)
{
    struct bf_chain *no_chain = NULL;

    expect_assert_failure(bf_cgen_new(NULL, BF_FRONT_CLI, NOT_NULL));
    expect_assert_failure(bf_cgen_new(NOT_NULL, BF_FRONT_CLI, NULL));
    expect_assert_failure(bf_cgen_new(NOT_NULL, BF_FRONT_CLI, &no_chain));
    expect_assert_failure(bf_cgen_free(NULL));
}

Test(cgen, create_delete)
{
    // Rely on the cleanup attribute.
    _cleanup_bf_cgen_ struct bf_cgen *cgen0 = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain0 = bf_test_chain_quick();

    assert_success(bf_cgen_new(&cgen0, BF_FRONT_CLI, &chain0));
    assert_non_null(cgen0);
    assert_null(chain0);

    // Codegen has the cleanup attribute, but call free() before
    _cleanup_bf_cgen_ struct bf_cgen *cgen1 = NULL;
    _cleanup_bf_chain_ struct bf_chain *chain1 = bf_test_chain_quick();

    assert_success(bf_cgen_new(&cgen1, BF_FRONT_CLI, &chain1));
    assert_non_null(cgen1);
    assert_null(chain1);

    bf_cgen_free(&cgen1);
    assert_null(cgen1);

    // Free the codegen manually
    struct bf_cgen *cgen2;
    _cleanup_bf_chain_ struct bf_chain *chain2 = bf_test_chain_quick();

    assert_success(bf_cgen_new(&cgen2, BF_FRONT_CLI, &chain2));
    assert_non_null(cgen2);
    assert_null(chain2);

    bf_cgen_free(&cgen2);
    assert_null(cgen2);
    bf_cgen_free(&cgen2);
}

Test(cgen, create_delete_no_malloc)
{
    _clean_bf_test_mock_ bf_test_mock mock;
    struct bf_cgen *cgen;
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_quick();

    mock = bf_test_mock_get(malloc, NULL);
    assert_error(bf_cgen_new(&cgen, BF_FRONT_CLI, &chain));
}

Test(cgen, marsh_unmarsh_assert)
{
    expect_assert_failure(bf_cgen_new_from_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_cgen_new_from_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_cgen_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_cgen_marsh(NOT_NULL, NULL));
}

Test(cgen, marsh_unmarsh)
{
    _cleanup_bf_cgen_ struct bf_cgen *cgen0 = NULL;
    _cleanup_bf_cgen_ struct bf_cgen *cgen1 = NULL;
    _cleanup_bf_marsh_ struct bf_marsh *marsh = NULL;

    /* Create a codegen without any program, other bf_program_unmarsh()
     * will try to open the pinned BPF objects.
     */
    cgen0 = bf_test_cgen(BF_FRONT_CLI, BF_HOOK_XDP, BF_VERDICT_ACCEPT);

    assert_success(bf_cgen_marsh(cgen0, &marsh));
    assert_success(bf_cgen_new_from_marsh(&cgen1, marsh));
    assert_non_null(cgen1);
}

Test(cgen, invalid_chain_policy)
{
    expect_assert_failure(bf_test_chain(BF_HOOK_XDP, BF_VERDICT_CONTINUE));
}
