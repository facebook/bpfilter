/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/ctx.c"

#include <stdbool.h>

#include "harness/cmocka.h"
#include "harness/mock.h"

Test(ctx, new_assert_failure)
{
    expect_assert_failure(_bf_ctx_new(NULL));
}

Test(ctx, new)
{
    _cleanup_bf_ctx_ struct bf_ctx *ctx = NULL;

    assert_return_code(_bf_ctx_new(&ctx), 0);

    _bf_ctx_free(&ctx);
    assert_null(ctx);
}

Test(ctx, new_malloc_fail)
{
    _cleanup_bf_ctx_ struct bf_ctx *ctx = NULL;

    will_return(__wrap_calloc, 0);
    bf_mock_calloc_enable();
    assert_true(_bf_ctx_new(&ctx) < 0);
    bf_mock_calloc_disable();
    assert_null(ctx);
}
