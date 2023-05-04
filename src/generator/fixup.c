// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "fixup.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "generator/codegen.h"
#include "shared/mem.h"

int bf_codegen_fixup_new(struct bf_codegen_fixup **fixup)
{
    __cleanup_bf_codegen_fixup__ struct bf_codegen_fixup *_fixup = NULL;

    assert(fixup);

    _fixup = calloc(1, sizeof(*_fixup));
    if (!_fixup)
        return -ENOMEM;

    *fixup = TAKE_PTR(_fixup);

    return 0;
}

void bf_codegen_fixup_free(struct bf_codegen_fixup **fixup)
{
    assert(fixup);

    if (!*fixup)
        return;

    free(*fixup);
    *fixup = NULL;
}
