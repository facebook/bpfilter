/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "generator/matcher/ip.h"

#include "core/logger.h"
#include "core/matcher.h"
#include "generator/fixup.h"
#include "generator/program.h"

static int _bf_matcher_generate_ip_addr(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    struct bf_matcher_ip_addr *addr = (void *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_IP_SRC_ADDR ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_L3, offset));
    if (addr->mask != 0xffffffff)
        EMIT(program, BPF_ALU32_IMM(BPF_AND, BF_REG_2, addr->mask));
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_IMM(matcher->op == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                           BF_REG_2, addr->addr, 0));

    return 0;
}

static int _bf_matcher_generate_ip_proto(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    uint16_t proto = *(uint16_t *)&matcher->payload;

    EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_4, BF_REG_L3,
                              offsetof(struct iphdr, protocol)));
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_IMM(BPF_JNE, BF_REG_4, proto, 0));

    return 0;
}

int bf_matcher_generate_ip(struct bf_program *program,
                           const struct bf_matcher *matcher)
{
    int r;

    switch (matcher->type) {
    case BF_MATCHER_IP_SRC_ADDR:
    case BF_MATCHER_IP_DST_ADDR:
        r = _bf_matcher_generate_ip_addr(program, matcher);
        break;
    case BF_MATCHER_IP_PROTO:
        r = _bf_matcher_generate_ip_proto(program, matcher);
        break;
    default:
        return bf_err_code(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    if (r)
        return r;

    return 0;
}
