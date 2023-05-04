/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "codegen.h"

#include <linux/if_ether.h>
#include <linux/ip.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "core/chain.h"
#include "core/logger.h"
#include "external/filter.h"
#include "generator/fixup.h"
#include "generator/progtype.h"
#include "shared/helper.h"
#include "shared/mem.h"

#define BF_CODEGEN_MAX_INSN (1 << 12)

int bf_codegen_new(struct bf_codegen **codegen)
{
    __cleanup_bf_codegen__ struct bf_codegen *_codegen = NULL;

    assert(codegen);

    _codegen = calloc(1, sizeof(*_codegen));
    if (!_codegen)
        return -ENOMEM;

    _codegen->img = malloc(BF_CODEGEN_MAX_INSN * sizeof(*_codegen->img));
    if (!_codegen->img)
        return -ENOMEM;

    _codegen->len_max = BF_CODEGEN_MAX_INSN;

    bf_list_init(
        &_codegen->fixups,
        (bf_list_ops[]) {{.free = (bf_list_ops_free)bf_codegen_fixup_free}});

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
    free((*codegen)->img);
    bf_list_clean(&(*codegen)->fixups);

    free(*codegen);
    *codegen = NULL;
}

int bf_codegen_emit(struct bf_codegen *codegen, struct bpf_insn insn)
{
    assert(codegen);

    if (codegen->len_cur == codegen->len_max) {
        bf_err("Codegen buffer overflow");
        return -EOVERFLOW;
    }

    codegen->img[codegen->len_cur++] = insn;

    return 0;
}

int bf_codegen_emit_fixup(struct bf_codegen *codegen,
                          enum bf_codegen_fixup_type type, struct bpf_insn insn)
{
    __cleanup_bf_codegen_fixup__ struct bf_codegen_fixup *fixup = NULL;
    int r;

    assert(codegen);

    if (codegen->len_cur == codegen->len_max) {
        bf_err("Codegen buffer overflow");
        return -EOVERFLOW;
    }

    r = bf_codegen_fixup_new(&fixup);
    if (r)
        return r;

    fixup->type = type;
    fixup->insn = codegen->len_cur;

    r = bf_list_add_tail(&codegen->fixups, fixup);
    if (r)
        return r;

    TAKE_PTR(fixup);

    /* This call could fail and return an error, in which case it is not
     * properly handled. However, this shouldn't be an issue as we previously
     * test whether enough room is available in codegen.img, which is currently
     * the only reason for EMIT() to fail. */
    EMIT(codegen, insn);

    return 0;
}

void bf_codegen_generate(enum bf_hooks hook, struct bf_codegen *codegen)
{
    enum bf_progtype type;
    const struct bf_progtype_ops *ops;

    assert(codegen);

    type = bf_hook_to_progtype(hook);
    ops = bf_progtype_ops_get(type);

    bf_info("Generating code for hook %s with program type %s",
            bf_hook_to_str(hook), bf_progtype_to_str(type));

    ops->gen_inline_prologue(codegen);
    ops->load_packet_data(codegen, CODEGEN_REG_L3);
    ops->load_packet_data_end(codegen, CODEGEN_REG_DATA_END);

    /* Store packet size */
    EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_SCRATCH2, CODEGEN_REG_DATA_END));
    EMIT(codegen, BPF_ALU64_REG(BPF_SUB, CODEGEN_REG_SCRATCH2, CODEGEN_REG_L3));
    EMIT(codegen,
         BPF_STX_MEM(BPF_W, CODEGEN_REG_RUNTIME_CTX, CODEGEN_REG_SCRATCH2,
                     STACK_RUNTIME_CONTEXT_OFFSET(data_size)));

    EMIT(codegen, BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_L3, ETH_HLEN));
    EMIT_FIXUP(codegen, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_REG(BPF_JGT, CODEGEN_REG_L3, CODEGEN_REG_DATA_END, 0));
    EMIT(codegen, BPF_MOV64_REG(CODEGEN_REG_SCRATCH1, CODEGEN_REG_L3));
    EMIT(codegen,
         BPF_ALU64_IMM(BPF_ADD, CODEGEN_REG_SCRATCH1, sizeof(struct iphdr)));
    EMIT_FIXUP(
        codegen, BF_CODEGEN_FIXUP_END_OF_CHAIN,
        BPF_JMP_REG(BPF_JGT, CODEGEN_REG_SCRATCH1, CODEGEN_REG_DATA_END, 0));

    ops->gen_inline_epilogue(codegen);
}

#define BF_DUMP_BUF_LEN 256
#define BF_INSN_CLASS_MASK 0b00000111
#define BF_INSN_LDST_MODE_MASK 0b11100000

#define BF_INSN_LDST_SIZE_MASK 0b00011000
#define bf_insn_get_ldst_size_str(insn)                                        \
    ({                                                                         \
        const char *_v = "INVALID";                                            \
        if (((insn)->code & BF_INSN_LDST_SIZE_MASK) >> 3 <=                    \
            ARRAY_SIZE(bpf_ldst_size))                                         \
            _v = bpf_ldst_size[((insn)->code & BF_INSN_LDST_SIZE_MASK) >> 3];  \
        _v;                                                                    \
    })

static const char *bpf_ldst_size[] = {
    "u32", // BPF_W
    "u16", // BPF_H
    "u8", // BPF_B
    "u64", // BPF_DW
};

static const char *bpf_reg[] = {
    "BPF_REG_0", "BPF_REG_1", "BPF_REG_2",  "BPF_REG_3",
    "BPF_REG_4", "BPF_REG_5", "BPF_REG_6",  "BPF_REG_7",
    "BPF_REG_8", "BPF_REG_9", "BPF_REG_10",
};

#define BF_INSN_ALU_CODE_MASK 0b11110000
#define bf_insn_get_alu_code_str(insn)                                         \
    ({                                                                         \
        const char *_v = "INVALID";                                            \
        if (((insn)->code & BF_INSN_ALU_CODE_MASK) >> 4 <=                     \
            ARRAY_SIZE(bpf_alu_code))                                          \
            _v = bpf_alu_code[((insn)->code & BF_INSN_ALU_CODE_MASK) >> 4];    \
        _v;                                                                    \
    })

static const char *bpf_alu_code[] = {
    "+", // BPF_ADD,
    "-", // BPF_SUB,
    "*", // BPF_MUL
    NULL, // BPF_DIV,
    "|", // BPF_OR
    "&", // BPF_AND
    "<<", // BPF_LSH
    ">>", // BPF_RSH
    NULL, // BPF_NEG
    NULL, // BPF_MOD
    "^", // BPF_XOR
    NULL, // BPF_MOV
    NULL, // BPF_ARSH
    NULL, // BPF_END
};

#define BF_INSN_JMP_CODE_MASK 0b11110000
#define bf_insn_get_jmp_code_str(insn)                                         \
    ({                                                                         \
        const char *_v = "INVALID";                                            \
        if (((insn)->code & BF_INSN_JMP_CODE_MASK) >> 4 <=                     \
            ARRAY_SIZE(bpf_jmp_code))                                          \
            _v = bpf_jmp_code[((insn)->code & BF_INSN_JMP_CODE_MASK) >> 4];    \
        _v;                                                                    \
    })

static const char *bpf_jmp_code[] = {
    NULL, // BPF_JA
    "==", // BPF_JEQ
    ">", // BPF_JGT
    ">=", // BPF_JGE
    "&", // BPF_JSET
    "!=", // BPF_JNE
    ">", // BPF_JSGT
    ">=", // BPF_JSGE
    NULL, // BPF_CALL
    NULL, // BPF_EXIT
    "<", // BPF_JLT
    "<=", // BPF_JLE
    "<", // BPF_JSLT
    "<=", // BPF_JSLE
};

#define BF_INSN_ALU_SIZE_MASK 0b00001000
#define bf_insn_get_alu_size_str(insn)                                         \
    ({                                                                         \
        const char *_v = "INVALID";                                            \
        if (((insn)->code & BF_INSN_ALU_SIZE_MASK) >> 3 <=                     \
            ARRAY_SIZE(bpf_alu_size))                                          \
            _v = bpf_alu_size[((insn)->code & BF_INSN_ALU_SIZE_MASK) >> 3];    \
        _v;                                                                    \
    })

static const char *bpf_alu_size[] = {
    "u32", // BPF_W
    "u64", // BPF_DW
};

static void bf_insn_alu_to_str(const struct bpf_insn *insn, char *buf)
{
    const char *size = bf_insn_get_alu_size_str(insn);
    const char *code = bf_insn_get_alu_code_str(insn);
    const char *dst_reg = bpf_reg[insn->dst_reg];
    const char *src_reg = bpf_reg[insn->src_reg];

    switch (insn->code & BF_INSN_ALU_CODE_MASK) {
    case BPF_ADD:
    case BPF_SUB:
    case BPF_MUL:
    case BPF_OR:
    case BPF_AND:
    case BPF_LSH:
    case BPF_RSH:
    case BPF_XOR:
        if (insn->code & BPF_X)
            snprintf(buf, BF_DUMP_BUF_LEN, "%s = (%s) ((%s) %s %s (%s) %s)",
                     dst_reg, size, size, dst_reg, code, size, src_reg);
        else
            snprintf(buf, BF_DUMP_BUF_LEN, "%s = (%s) ((%s) %s %s (%s) %d)",
                     dst_reg, size, size, dst_reg, code, size, insn->imm);
        break;
    case BPF_MOV:
        if (insn->code & BPF_X)
            snprintf(buf, BF_DUMP_BUF_LEN, "%s = (%s) %s", dst_reg, size,
                     src_reg);
        else
            snprintf(buf, BF_DUMP_BUF_LEN, "%s = (%s) %d", dst_reg, size,
                     insn->imm);
        break;
    default:
        snprintf(buf, BF_DUMP_BUF_LEN, "<unknown ALU instruction 0x%02X>",
                 (insn->code & BF_INSN_ALU_CODE_MASK));
        break;
    };
}

static void bf_insn_jmp_to_str(const struct bpf_insn *insn, char *buf)
{
    const char *dst_reg = bpf_reg[insn->dst_reg];
    const char *src_reg = bpf_reg[insn->src_reg];
    const char *code = bf_insn_get_jmp_code_str(insn);

    assert(insn);
    assert(buf);

    switch (insn->code & BF_INSN_JMP_CODE_MASK) {
    case BPF_JA:
        snprintf(buf, BF_DUMP_BUF_LEN, "goto 0x%02x", insn->off);
        break;
    case BPF_JEQ:
    case BPF_JGT:
    case BPF_JGE:
    case BPF_JSET:
    case BPF_JNE:
    case BPF_JSGT:
    case BPF_JSGE:
    case BPF_JLT:
    case BPF_JLE:
    case BPF_JSLT:
    case BPF_JSLE:
        snprintf(buf, BF_DUMP_BUF_LEN, "if (%s %s %s) goto 0x%02x", dst_reg,
                 code, src_reg, insn->off);
        break;
    case BPF_CALL:
        snprintf(buf, BF_DUMP_BUF_LEN, "calling function");
        break;
    case BPF_EXIT:
        snprintf(buf, BF_DUMP_BUF_LEN, "exit");
        break;
    default:
        snprintf(buf, BF_DUMP_BUF_LEN, "<unknown JMP instruction 0x%02X>",
                 (insn->code & BF_INSN_ALU_CODE_MASK));
        break;
    };
}

static void bf_insn_ldst_to_str(const struct bpf_insn *insn, char *buf)
{
    const char *size = bf_insn_get_ldst_size_str(insn);
    const char *dst_reg = bpf_reg[insn->dst_reg];
    const char *src_reg = bpf_reg[insn->src_reg];

    assert(insn);
    assert(buf);

    switch (insn->code & (BF_INSN_LDST_MODE_MASK | BF_INSN_CLASS_MASK)) {
    case BPF_MEM | BPF_STX:
        snprintf(buf, BF_DUMP_BUF_LEN, "*(%s *) (%s + 0x%02x) = %s", size,
                 dst_reg, insn->off, src_reg);
        break;
    case BPF_MEM | BPF_ST:
        snprintf(buf, BF_DUMP_BUF_LEN, "*(%s *) (%s + 0x%02x) = %d", size,
                 dst_reg, insn->off, insn->imm);
        break;
    case BPF_MEM | BPF_LDX:
        snprintf(buf, BF_DUMP_BUF_LEN, "%s = *(%s *) (%s + 0x%02x)", dst_reg,
                 size, src_reg, insn->off);
        break;
    default:
        snprintf(buf, BF_DUMP_BUF_LEN, "<unknown LD/ST instruction 0x%02X>",
                 (insn->code & BF_INSN_LDST_MODE_MASK));
        break;
    };
}

static void bf_insn_to_str(const struct bpf_insn *insn, char *buf)
{
    assert(insn);
    assert(buf);

    switch (insn->code & BF_INSN_CLASS_MASK) {
    case BPF_ALU:
    case BPF_ALU64:
        bf_insn_alu_to_str(insn, buf);
        break;
    case BPF_JMP:
    case BPF_JMP32:
        bf_insn_jmp_to_str(insn, buf);
        break;
    case BPF_LD:
    case BPF_LDX:
    case BPF_ST:
    case BPF_STX:
        bf_insn_ldst_to_str(insn, buf);
        break;
    default:
        snprintf(buf, BF_DUMP_BUF_LEN, "<unkown instruction class 0x%02x>",
                 insn->code & BF_INSN_CLASS_MASK);
        break;
    };
}

void bf_codegen_dump_bytecode(struct bf_codegen *codegen)
{
    char buf[BF_DUMP_BUF_LEN];

    assert(codegen);

    bf_info("Dumping bytecode:");

    for (size_t i = 0; i < codegen->len_cur; i++) {
        bf_insn_to_str(&codegen->img[i], buf);
        bf_info("  [0x%04lx] %s", i * sizeof(codegen->img[0]), buf);
    }
}
