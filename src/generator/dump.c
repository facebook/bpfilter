// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/dump.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <assert.h>
#include <stdio.h>

#include "core/dump.h"
#include "core/logger.h"
#include "generator/program.h"
#include "shared/helper.h"

#define BF_INSN_CLS(insn) ((insn)->code & 0b00000111)
#define BF_INSN_CODE(insn) ((insn)->code & 0b11110000)
#define BF_INSN_SRC(insn) ((insn)->code & 0b00001000)
#define BF_INSN_MODE(insn) ((insn)->code & 0b11100000)
#define BF_INSN_SIZE(insn) ((insn)->code & 0b00011000)

#define BF_IMM_BUF_LEN 16

static const char *_bpf_reg(unsigned char reg)
{
    static const char *regs[] = {
        [BPF_REG_0] = "BPF_REG_0",   [BPF_REG_1] = "BPF_REG_1",
        [BPF_REG_2] = "BPF_REG_2",   [BPF_REG_3] = "BPF_REG_3",
        [BPF_REG_4] = "BPF_REG_4",   [BPF_REG_5] = "BPF_REG_5",
        [BPF_REG_6] = "BPF_REG_6",   [BPF_REG_7] = "BPF_REG_7",
        [BPF_REG_8] = "BPF_REG_8",   [BPF_REG_9] = "BPF_REG_9",
        [BPF_REG_10] = "BPF_REG_10",
    };

    assert(reg < __MAX_BPF_REG);
    static_assert(ARRAY_SIZE(regs) == __MAX_BPF_REG);

    return regs[reg];
}

static const char *_bf_op(const struct bpf_insn *insn)
{
    static const char *ops[] = {
        [BPF_ADD >> 4] = "+",  [BPF_SUB >> 4] = "-", [BPF_MUL >> 4] = "*",
        [BPF_OR >> 4] = "|",   [BPF_AND >> 4] = "&", [BPF_LSH >> 4] = "<<",
        [BPF_RSH >> 4] = ">>", [BPF_XOR >> 4] = "^",
    };

    unsigned code = BF_INSN_CODE(insn) >> 4;

    assert(code < ARRAY_SIZE(ops));

    return ops[code];
}

static const char *_bf_src(const struct bpf_insn *insn,
                           char (*imm_buf)[BF_IMM_BUF_LEN])
{
    assert(insn);
    assert(imm_buf);

    if (BF_INSN_SRC(insn))
        return _bpf_reg(insn->src_reg);

    snprintf(*imm_buf, BF_IMM_BUF_LEN, "%d", insn->imm);

    return *imm_buf;
}

static void _bf_program_dump_alu_insn(const struct bf_program *program,
                                      size_t *insn_idx, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;
    char imm_buf[BF_IMM_BUF_LEN] = {};
    const struct bpf_insn *insn = &program->img[*insn_idx];
    const char *size = BF_INSN_CLS(insn) == BPF_ALU64 ? "" : "(u32)";

    switch (BF_INSN_CODE(insn)) {
    case BPF_ADD:
    case BPF_SUB:
    case BPF_MUL:
    case BPF_OR:
    case BPF_AND:
    case BPF_LSH:
    case BPF_RSH:
    case BPF_XOR:
        DUMP(prefix, "%04lu %s = %s%s %s %s%s", *insn_idx,
             _bpf_reg(insn->dst_reg), size, _bpf_reg(insn->dst_reg),
             _bf_op(insn), size, _bf_src(insn, &imm_buf));
        break;
    case BPF_DIV:
        DUMP(prefix, "%04lu BPF_DIV - Unsupported", *insn_idx);
        break;
    case BPF_MOD:
        DUMP(prefix, "%04lu BPF_MOD - Unsupported", *insn_idx);
        break;
    case BPF_NEG:
        DUMP(prefix, "%04lu %s = ~%s%s", *insn_idx, _bpf_reg(insn->dst_reg),
             size, _bf_src(insn, &imm_buf));
        break;
    case BPF_MOV:
        DUMP(prefix, "%04lu %s = %s%s", *insn_idx, _bpf_reg(insn->dst_reg),
             size, _bf_src(insn, &imm_buf));
        break;
    case BPF_ARSH:
        DUMP(prefix, "%04lu BPF_ARSH - Unsupported", *insn_idx);
        break;
    case BPF_END:
        DUMP(prefix, "%04lu BPF_END - Unsupported", *insn_idx);
        break;
    };
}

static const char *_bf_jmp_op(const struct bpf_insn *insn)
{
    static const char *ops[] = {
        [BPF_JEQ >> 4] = "==",   [BPF_JGT >> 4] = ">",
        [BPF_JGE >> 4] = ">=",   [BPF_JSET >> 4] = "&",
        [BPF_JNE >> 4] = "!=",   [BPF_JSGT >> 4] = "s>",
        [BPF_JSGE >> 4] = "s>=", [BPF_JLT >> 4] = "<",
        [BPF_JLE >> 4] = "<=",   [BPF_JSLT >> 4] = "s<",
        [BPF_JSLE >> 4] = "s<=",
    };

    int code = BF_INSN_CODE(insn) >> 4;

    assert(0 <= code && code < (int)ARRAY_SIZE(ops));

    return ops[code];
}

static const char *_bpf_helper(const struct bpf_insn *insn)
{
    static const char *funcs[] = {
        [BPF_FUNC_map_lookup_elem] = "map_lookup_elem",
        [BPF_FUNC_map_update_elem] = "map_update_elem",
    };

    return funcs[insn->imm];
}

static void _bf_program_dump_jmp_insn(const struct bf_program *program,
                                      size_t *insn_idx, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;
    char imm_buf[BF_IMM_BUF_LEN] = {};
    const struct bpf_insn *insn = &program->img[*insn_idx];
    const char *size = BF_INSN_CLS(insn) == BPF_ALU ? "" : "(u32)";

    assert(program);
    assert(insn_idx);

    switch (BF_INSN_CODE(insn)) {
    case BPF_JA:
        if (insn->off == 0) {
            DUMP(prefix, "%04lu noop", *insn_idx);
        } else {
            DUMP(prefix, "%04lu goto pc + %d", *insn_idx,
                 program->img[*insn_idx].off);
        }
        break;
    case BPF_JEQ:
    case BPF_JGT:
    case BPF_JGE:
    case BPF_JSET:
    case BPF_JNE:
    case BPF_JLT:
    case BPF_JLE:
    case BPF_JSGT:
    case BPF_JSGE:
    case BPF_JSLT:
    case BPF_JSLE:
        DUMP(prefix, "%04lu if %s%s %s %s%s goto pc + %d", *insn_idx, size,
             _bpf_reg(insn->dst_reg), _bf_jmp_op(insn), size,
             _bf_src(insn, &imm_buf), insn->off);
        break;
    case BPF_CALL:
        switch (insn->src_reg) {
        case 0x00:
            DUMP(prefix, "%04lu call %s", *insn_idx, _bpf_helper(insn));
            break;
        case 0x01:
            DUMP(prefix, "%04lu call pc + %d", *insn_idx, insn->imm);
            break;
        case 0x02:
            DUMP(prefix, "%04lu call helper function by BTF ID", *insn_idx);
            break;
        };
        break;
    case BPF_EXIT:
        DUMP(prefix, "%04lu exit", *insn_idx);
        break;
    };
}

static const char *_bpf_ldst_size(const struct bpf_insn *insn)
{
    static const char *sizes[] = {
        [BPF_W >> 3] = "u32",
        [BPF_H >> 3] = "u16",
        [BPF_B >> 3] = "u8",
        [BPF_DW >> 3] = "u64",
    };

    unsigned char size = BF_INSN_SIZE(insn) >> 3;

    assert(size < (int)ARRAY_SIZE(sizes));

    return sizes[size];
}

static void _bf_program_dump_imm64_insn(const struct bf_program *program,
                                        size_t *insn_idx, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;
    const struct bpf_insn *insn = &program->img[*insn_idx];
    const struct bpf_insn *next_insn;

    assert(program);
    assert(insn_idx);
    assert(prefix);

    assert((*insn_idx + 1) < program->img_size);

    next_insn = &program->img[*insn_idx + 1];

    (*insn_idx)++; // Skip the next one as this is a 64 bits immediate value
                   // instruction.

    assert(insn->code == (BPF_IMM | BPF_DW | BPF_LD));

    switch (insn->src_reg) {
    case 0x00:
        DUMP(prefix, "%04lu %s = %llu", *insn_idx, _bpf_reg(insn->dst_reg),
             ((unsigned long long)insn->imm << 32) | next_insn->imm);
        break;
    case 0x01:
        DUMP(prefix, "%04lu %s = map_by_fd(%d)", *insn_idx,
             _bpf_reg(insn->dst_reg), insn->imm);
        break;
    case 0x02:
        DUMP(prefix, "%04lu %s = map_val(map_by_fd(%d)) + %d", *insn_idx,
             _bpf_reg(insn->dst_reg), insn->imm, next_insn->imm);
        break;
    case 0x03:
        DUMP(prefix, "%04lu %s = val_addr(%d)", *insn_idx,
             _bpf_reg(insn->dst_reg), insn->imm);
        break;
    case 0x04:
        DUMP(prefix, "%04lu %s = code_addr(%d)", *insn_idx,
             _bpf_reg(insn->dst_reg), insn->imm);
        break;
    case 0x05:
        DUMP(prefix, "%04lu %s = map_by_idx(%d)", *insn_idx,
             _bpf_reg(insn->dst_reg), insn->imm);
        break;
    case 0x06:
        DUMP(prefix, "%04lu %s = map_val(map_by_idx(%d)) + %d", *insn_idx,
             _bpf_reg(insn->dst_reg), insn->imm, next_insn->imm);
        break;
    }
}

static void _bf_program_dump_ldst_insn(const struct bf_program *program,
                                       size_t *insn_idx, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;
    const struct bpf_insn *insn = &program->img[*insn_idx];

    switch (BF_INSN_MODE(insn)) {
    case BPF_IMM:
        _bf_program_dump_imm64_insn(program, insn_idx, prefix);
        break;
    case BPF_ABS:
    case BPF_IND:
        DUMP(prefix, "%04lu legacy BPF instructions are not supported",
             *insn_idx);
        break;
    case BPF_MEM:
        switch (BF_INSN_CLS(insn)) {
        case BPF_LDX:
            DUMP(prefix, "%04lu %s = *(%s *)(%s + %d)", *insn_idx,
                 _bpf_reg(insn->dst_reg), _bpf_ldst_size(insn),
                 _bpf_reg(insn->src_reg), insn->off);
            break;
        case BPF_ST:
            DUMP(prefix, "%04lu *(%s *)(%s + %d) = %d", *insn_idx,
                 _bpf_ldst_size(insn), _bpf_reg(insn->dst_reg), insn->off,
                 insn->imm);
            break;
        case BPF_STX:
            DUMP(prefix, "%04lu *(%s *)(%s + %d) = %s", *insn_idx,
                 _bpf_ldst_size(insn), _bpf_reg(insn->dst_reg), insn->off,
                 _bpf_reg(insn->src_reg));
            break;
        };
        break;
    case BPF_ATOMIC:
        DUMP(prefix, "%04lu BPF_ATOMIC - Unsupported", *insn_idx);
        break;
    }
}

static void _bf_program_dump_insn(const struct bf_program *program,
                                  size_t *insn_idx, prefix_t *prefix)
{
    prefix_t _prefix = {};
    prefix = prefix ?: &_prefix;
    const struct bpf_insn *insn = &program->img[*insn_idx];

    switch (BF_INSN_CLS(insn)) {
    case BPF_LD:
    case BPF_LDX:
    case BPF_ST:
    case BPF_STX:
        _bf_program_dump_ldst_insn(program, insn_idx, prefix);
        break;
    case BPF_ALU:
    case BPF_ALU64:
        _bf_program_dump_alu_insn(program, insn_idx, prefix);
        break;
    case BPF_JMP:
    case BPF_JMP32:
        _bf_program_dump_jmp_insn(program, insn_idx, prefix);
        break;
    default:
        DUMP(prefix, "%04lu Unknown insn code: 0x%02x", *insn_idx,
             program->img[*insn_idx].code);
        break;
    };
}

static void _bf_program_dump_raw(const struct bf_program *program,
                                 size_t *insn_idx, prefix_t *prefix)
{
    const struct bpf_insn *insn = &program->img[*insn_idx];

    switch (BF_INSN_CLS(&program->img[*insn_idx])) {
    case BPF_LD:
    case BPF_LDX:
    case BPF_STX:
    case BPF_ST:
        DUMP(prefix,
             "mode=0x%02x, size=0x%02x, cls=0x%02x, dst=%s, src=%s, imm=%d",
             BF_INSN_MODE(insn), BF_INSN_SIZE(insn), BF_INSN_CLS(insn),
             _bpf_reg(insn->dst_reg), _bpf_reg(insn->src_reg), insn->imm);
        break;
    case BPF_ALU:
    case BPF_ALU64:
    case BPF_JMP:
    case BPF_JMP32:
        DUMP(prefix,
             "code=0x%02x, src=0x%02x, cls=0x%02x, dst=%s, src=%s, imm=%d",
             BF_INSN_CODE(insn), BF_INSN_SRC(insn), BF_INSN_CLS(insn),
             _bpf_reg(insn->dst_reg), _bpf_reg(insn->src_reg), insn->imm);
        break;
    };
}

void bf_program_dump_bytecode(const struct bf_program *program, bool with_raw)
{
    size_t i;
    prefix_t prefix = {};

    bf_dump_prefix_push(&prefix);

    bf_dbg("Bytecode for program at %p, %lu insn:", program, program->img_size);

    for (i = 0; i < program->img_size; ++i) {
        if (i == program->img_size - 1)
            bf_dump_prefix_last(&prefix);

        _bf_program_dump_insn(program, &i, &prefix);

        if (with_raw) {
            bf_dump_prefix_push(&prefix);
            bf_dump_prefix_last(&prefix);
            _bf_program_dump_raw(program, &i, &prefix);
            bf_dump_prefix_pop(&prefix);
        }
    }

    // Force flush, otherwise output on stderr might appear.
    fflush(stdout);
}
