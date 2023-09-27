/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/context.c"

#include <stdbool.h>

#include "harness/cmocka.h"
#include "harness/mock.h"

Test(context, new_assert_failure)
{
    expect_assert_failure(_bf_context_new(NULL));
}

Test(context, new)
{
    _cleanup_bf_context_ struct bf_context *context = NULL;

    assert_return_code(_bf_context_new(&context), 0);

    _bf_context_free(&context);
    assert_null(context);
}

Test(context, new_malloc_fail)
{
    _cleanup_bf_context_ struct bf_context *context = NULL;

    will_return(__wrap_calloc, 0);
    bf_mock_calloc_enable();
    assert_true(_bf_context_new(&context) < 0);
    bf_mock_calloc_disable();
    assert_null(context);
}
