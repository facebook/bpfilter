/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/cgen.c"

#include "harness/cmocka.h"
#include "harness/helper.h"
#include "harness/mock.h"

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
    _cleanup_bf_mock_ bf_mock mock; 
    struct bf_cgen *cgen;
    _cleanup_bf_chain_ struct bf_chain *chain = bf_test_chain_quick();

    mock = bf_mock_get(malloc, NULL);
    assert_error(bf_cgen_new(&cgen, BF_FRONT_CLI, &chain));
}

Test(cgen, marsh_unmarsh_assert)
{
    expect_assert_failure(bf_cgen_new_from_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_cgen_new_from_marsh(NOT_NULL, NULL));
    expect_assert_failure(bf_cgen_marsh(NULL, NOT_NULL));
    expect_assert_failure(bf_cgen_marsh(NOT_NULL, NULL));
} 

Test(cgen, get_program)
{
    _cleanup_bf_cgen_ struct bf_cgen *cgen = NULL;

    cgen = bf_test_cgen(BF_FRONT_IPT, BF_HOOK_NF_FORWARD, BF_VERDICT_ACCEPT, 5);
    assert_non_null(cgen);

    {
        // Get first program in the list
        struct bf_program *program = bf_cgen_get_program(cgen, 1);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 1);
    }

    {
        // Get program from the middle of the list
        struct bf_program *program = bf_cgen_get_program(cgen, 3);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 3);
    }

    {
        // Get last program of the list
        struct bf_program *program = bf_cgen_get_program(cgen, 5);
        assert_non_null(program);
        assert_int_equal(program->ifindex, 5);
    }

    {
        // Get program with an invalid interface
        struct bf_program *program = bf_cgen_get_program(cgen, 10);
        assert_null(program);
    }
}
