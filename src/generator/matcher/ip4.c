/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "generator/matcher/ip4.h"

#include <endian.h>

#include "core/logger.h"
#include "core/matcher.h"
#include "generator/fixup.h"
#include "generator/program.h"

static int
_bf_matcher_generate_ip4_addr_unique(struct bf_program *program,
                                     const struct bf_matcher *matcher)
{
    struct bf_matcher_ip4_addr *addr = (void *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_IP4_SRC_ADDR ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_1, BF_REG_L3, offset));
    EMIT(program, BPF_MOV32_IMM(BF_REG_2, addr->addr));

    if (addr->mask != 0xffffffff) {
        EMIT(program, BPF_MOV32_IMM(BF_REG_3, addr->mask));
        EMIT(program, BPF_ALU32_REG(BPF_AND, BF_REG_2, BF_REG_3));
    }

    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_REG(matcher->op == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                           BF_REG_1, BF_REG_2, 0));

    return 0;
}

static int _bf_matcher_generate_ip4_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    switch (matcher->op) {
    case BF_MATCHER_EQ:
    case BF_MATCHER_NE:
        return _bf_matcher_generate_ip4_addr_unique(program, matcher);
    case BF_MATCHER_IN:
        return 0;
    default:
        return -EINVAL;
    }

    return 0;
}

static int _bf_matcher_generate_ip4_proto(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    uint8_t proto = *(uint8_t *)&matcher->payload;

    EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_4, BF_REG_L3,
                              offsetof(struct iphdr, protocol)));
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_IMM(matcher->op == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                           BF_REG_4, proto, 0));

    return 0;
}

int bf_matcher_generate_ip4(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_IMM(BPF_JNE, BF_REG_1, htobe16(ETH_P_IP), 0));

    switch (matcher->type) {
    case BF_MATCHER_IP4_SRC_ADDR:
    case BF_MATCHER_IP4_DST_ADDR:
        r = _bf_matcher_generate_ip4_addr(program, matcher);
        break;
    case BF_MATCHER_IP4_PROTO:
        r = _bf_matcher_generate_ip4_proto(program, matcher);
        break;
    default:
        return bf_err_code(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    if (r)
        return r;

    return 0;
}
