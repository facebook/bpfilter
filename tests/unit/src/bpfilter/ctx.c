/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/ctx.c"

#include <stdbool.h>

#include "harness/test.h"
#include "harness/mock.h"

Test(ctx, create_delete_assert)
{
    expect_assert_failure(_bf_ctx_new(NULL));
    expect_assert_failure(_bf_ctx_free(NULL));
}

Test(ctx, create_delete)
{
    // Rely on the cleanup attrubte
    _cleanup_bf_ctx_ struct bf_ctx *ctx0 = NULL;

    assert_success(_bf_ctx_new(&ctx0));
    assert_non_null(ctx0);

    // Use the cleanup attribute, but free manually
    _cleanup_bf_ctx_ struct bf_ctx *ctx1 = NULL;

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
