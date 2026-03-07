/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/jmp.h"

#include <linux/bpf.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>

#include "cgen/program.h"

void bf_jmpctx_cleanup(struct bf_jmpctx *ctx)
{
    if (ctx->program) {
        struct bpf_insn *insn = &ctx->program->img[ctx->insn_idx];
        size_t off = ctx->program->img_size - ctx->insn_idx - 1U;

        if (off > SHRT_MAX)
            bf_warn("jump offset overflow: %ld", off);

        insn->off = (int16_t)off;
    }
}
