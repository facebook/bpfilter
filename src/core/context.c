/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "context.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/list.h"
#include "generator/codegen.h"

void bf_context_init(struct bf_context *context)
{
    assert(context);

    for (int i = 0; i < __BF_HOOK_MAX; ++i)
        bf_list_init(
            &context->hooks[i],
            (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_codegen_free}});
}

void bf_context_clean(struct bf_context *context)
{
    for (int i = 0; i < __BF_HOOK_MAX; ++i)
        bf_list_clean(&context->hooks[i]);
}
