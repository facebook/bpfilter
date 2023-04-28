/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "codegen.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "core/chain.h"
#include "shared/mem.h"

int bf_codegen_new(struct bf_codegen **codegen)
{
    __cleanup_bf_codegen__ struct bf_codegen *_codegen = NULL;

    assert(codegen);

    _codegen = calloc(1, sizeof(*_codegen));
    if (!_codegen)
        return -ENOMEM;

    *codegen = TAKE_PTR(_codegen);

    return 0;
}

void bf_codegen_free(struct bf_codegen **codegen)
{
    assert(codegen);

    if (!*codegen)
        return;

    bf_chain_free(&(*codegen)->chain);
    free((*codegen)->src_data);

    free(*codegen);
    *codegen = NULL;
}
