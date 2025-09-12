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
    _free_bf_cgen_ struct bf_cgen *cgen0 = NULL;
    _free_bf_chain_ struct bf_chain *chain0 = bf_test_chain_quick();

    assert_success(bf_cgen_new(&cgen0, BF_FRONT_CLI, &chain0));
    assert_non_null(cgen0);
    assert_null(chain0);

    // Codegen has the cleanup attribute, but call free() before
    _free_bf_cgen_ struct bf_cgen *cgen1 = NULL;
    _free_bf_chain_ struct bf_chain *chain1 = bf_test_chain_quick();

    assert_success(bf_cgen_new(&cgen1, BF_FRONT_CLI, &chain1));
    assert_non_null(cgen1);
    assert_null(chain1);

    bf_cgen_free(&cgen1);
    assert_null(cgen1);

    // Free the codegen manually
    struct bf_cgen *cgen2;
    _free_bf_chain_ struct bf_chain *chain2 = bf_test_chain_quick();

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
    _free_bf_chain_ struct bf_chain *chain = bf_test_chain_quick();

    mock = bf_test_mock_get(malloc, NULL);
    assert_error(bf_cgen_new(&cgen, BF_FRONT_CLI, &chain));
}

Test(cgen, pack_unpack)
{
    _free_bf_cgen_ struct bf_cgen *cgen0 = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen1 = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    expect_assert_failure(bf_cgen_pack(NULL, NOT_NULL));
    expect_assert_failure(bf_cgen_pack(NOT_NULL, NULL));

    assert_non_null(cgen0 = bf_test_cgen(BF_FRONT_CLI, BF_HOOK_XDP, BF_VERDICT_ACCEPT));

    assert_success(bf_wpack_new(&wpack));
    assert_success(bf_cgen_pack(cgen0, wpack));
    assert_success(bf_wpack_get_data(wpack, &data, &data_len));

    assert_success(bf_rpack_new(&rpack, data, data_len));
    assert_success(bf_cgen_new_from_pack(&cgen1, bf_rpack_root(rpack)));
}

Test(cgen, invalid_chain_policy)
{
    expect_assert_failure(bf_test_chain(BF_HOOK_XDP, BF_VERDICT_CONTINUE));
}
