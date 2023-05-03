/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "tc.h"

#include <linux/pkt_cls.h>

#include "core/logger.h"
#include "external/filter.h"
#include "generator/codegen.h"
#include "shared/helper.h"

void tc_gen_inline_prologue(struct bf_codegen *codegen);
void tc_load_packet_data(struct bf_codegen *codegen, int reg);
void tc_load_packet_data_end(struct bf_codegen *codegen, int reg);
void tc_gen_inline_epilogue(struct bf_codegen *codegen);

const struct bf_progtype_ops bf_progtype_ops_tc = {
    .gen_inline_prologue = tc_gen_inline_prologue,
    .load_packet_data = tc_load_packet_data,
    .load_packet_data_end = tc_load_packet_data_end,
    .gen_inline_epilogue = tc_gen_inline_epilogue,
};

void tc_gen_inline_prologue(struct bf_codegen *codegen)
{
    assert(codegen);

    bf_dbg("tc_gen_inline_prologue");

    EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_CTX, BPF_REG_ARG1));
    EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_RUNTIME_CTX, BPF_REG_FP));
    EMIT(codegen, BPF_MOV32_IMM(CODEGEN_REG_RETVAL, TC_ACT_OK));
}

void tc_load_packet_data(struct bf_codegen *codegen, int reg)
{
    assert(codegen);

    bf_dbg("tc_load_packet_data");

    EMIT(codegen, BPF_LDX_MEM(BPF_W, reg, CODEGEN_REG_CTX,
                              offsetof(struct __sk_buff, data)));
}

void tc_load_packet_data_end(struct bf_codegen *codegen, int reg)
{
    UNUSED(reg);

    assert(codegen);

    bf_dbg("tc_load_packet_data_end");

    EMIT(codegen, BPF_LDX_MEM(BPF_W, CODEGEN_REG_DATA_END, CODEGEN_REG_CTX,
                              offsetof(struct __sk_buff, data_end)));
}

void tc_gen_inline_epilogue(struct bf_codegen *codegen)
{
    assert(codegen);

    bf_dbg("tc_gen_inline_epilogue");

    EMIT(codegen, BPF_EXIT_INSN());
}
