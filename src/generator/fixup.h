/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <stddef.h>

#include "core/list.h"

enum bf_codegen_fixup_type
{
    BF_CODEGEN_FIXUP_NEXT_RULE,
    BF_CODEGEN_FIXUP_END_OF_CHAIN,
    BF_CODEGEN_FIXUP_JUMP_TO_CHAIN,
    BF_CODEGEN_FIXUP_COUNTERS_INDEX,
    __BF_CODEGEN_FIXUP_MAX
};

struct bf_codegen_fixup
{
    enum bf_codegen_fixup_type type;
    size_t insn;

    union
    {
        size_t offset;
    };
};

struct bf_codegen;

#define __cleanup_bf_codegen_fixup__                                           \
    __attribute__((cleanup(bf_codegen_fixup_free)))

int bf_codegen_fixup_new(struct bf_codegen_fixup **fixup);
void bf_codegen_fixup_free(struct bf_codegen_fixup **fixup);

int bf_codegen_fixup_emit(struct bf_codegen *codegen,
                          enum bf_codegen_fixup_type type,
                          struct bpf_insn insn);
