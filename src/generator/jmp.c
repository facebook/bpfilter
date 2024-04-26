/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/jmp.h"

#include "generator/program.h"

void bf_jmpctx_cleanup(struct bf_jmpctx *ctx)
{
    struct bpf_insn *insn = &ctx->program->img[ctx->insn_idx];
    insn->off = ctx->program->img_size - ctx->insn_idx - 1U;
}
