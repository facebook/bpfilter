/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/ctx.c"

#include <stdbool.h>

#include "harness/test.h"
#include "fake.h"
#include "mock.h"

Test(ctx, create_delete_assert)
{
    expect_assert_failure(_bf_ctx_new(NULL));
    expect_assert_failure(_bf_ctx_free(NULL));
}

Test(ctx, create_delete)
{
    _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_empty(bf_btf_get_id);
    bf_test_mock_will_return_always(_, 1);

    // Rely on the cleanup attrubte
    _free_bf_ctx_ struct bf_ctx *ctx0 = NULL;

    assert_success(_bf_ctx_new(&ctx0));
    assert_non_null(ctx0);

    // Use the cleanup attribute, but free manually
    _free_bf_ctx_ struct bf_ctx *ctx1 = NULL;

    assert_success(_bf_ctx_new(&ctx1));
    assert_non_null(ctx1);

    _bf_ctx_free(&ctx1);
    assert_null(ctx1);

    // Free manually
    struct bf_ctx *ctx2;

    assert_success(_bf_ctx_new(&ctx2));
    assert_non_null(ctx2);

    _bf_ctx_free(&ctx2);
    assert_null(ctx2);
    _bf_ctx_free(&ctx2);
}

Test(ctx, set_get_chain)
{
    _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_empty(bf_btf_get_id);
    bf_test_mock_will_return_always(_, 1);

    // Rely on the cleanup attrubte
    _free_bf_ctx_ struct bf_ctx *ctx = NULL;
    _free_bf_cgen_ struct bf_cgen *cgen0 = bf_test_cgen_quick();
    _free_bf_cgen_ struct bf_cgen *cgen1 = bf_test_cgen_quick();
    _free_bf_cgen_ struct bf_cgen *cgen2 = bf_test_cgen_quick();

    // Change the name of cgen2
    freep(&cgen2->chain->name);
    cgen2->chain->name = strdup("hello");
    assert_non_null(cgen2->chain->name);

    assert_success(_bf_ctx_new(&ctx));
    // Do not free cgens, as we keep a reference here
    ctx->cgens.ops.free = NULL;

    // Context is empty, add the first cgen
    assert_success(_bf_ctx_set_cgen(ctx, cgen0));

    // Trying to add another cgen with the same name
    assert_error(_bf_ctx_set_cgen(ctx, cgen1));

    // Add another cgen with a different name
    assert_success(_bf_ctx_set_cgen(ctx, cgen2));

    // Get the cgens back
    assert_ptr_equal(_bf_ctx_get_cgen(ctx, cgen0->chain->name), cgen0);
    assert_ptr_equal(_bf_ctx_get_cgen(ctx, cgen1->chain->name), cgen0);
    assert_ptr_equal(_bf_ctx_get_cgen(ctx, cgen2->chain->name), cgen2);
}
