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

int bf_codegen_fixup_emit(struct bf_codegen *codegen,
                          enum bf_codegen_fixup_type type, struct bpf_insn insn)
{
    __cleanup_bf_codegen_fixup__ struct bf_codegen_fixup *fixup = NULL;
    int r;

    assert(codegen);

    r = bf_codegen_fixup_new(&fixup);
    if (r)
        return r;

    fixup->type = type;
    fixup->insn = codegen->len_cur;

    r = bf_list_add_tail(&codegen->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    EMIT(codegen, insn);

    return 0;
}
