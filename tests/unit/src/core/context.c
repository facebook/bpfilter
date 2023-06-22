/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#include "core/context.c"

#include <criterion/criterion.h>

#include "test.h"

Test(src_core_context, new)
{
    _cleanup_bf_context_ struct bf_context *context = NULL;

    cr_assert_eq(0, _bf_context_new(&context));

    _bf_context_free(&context);
    cr_assert_eq(context, NULL);
}

TestAssert(src_core_context, _bf_context_new, 0, (NULL));
