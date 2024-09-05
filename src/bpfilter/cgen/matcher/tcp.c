/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/tcp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/tcp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/fixup.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "core/logger.h"
#include "core/matcher.h"

#include "external/filter.h"

static int _bf_matcher_generate_tcp_port(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    uint16_t port = *(uint16_t *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_TCP_SPORT ?
                        offsetof(struct tcphdr, source) :
                        offsetof(struct tcphdr, dest);

    EMIT(program, BPF_LDX_MEM(BPF_H, BF_REG_4, BF_REG_L4, offset));
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_IMM(matcher->op == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                           BF_REG_4, htobe16(port), 0));

    return 0;
}

static int _bf_matcher_generate_tcp_flags(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    uint8_t flags = *(uint8_t *)matcher->payload;

    EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_L4, 13));

    switch (matcher->op) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
                   BPF_JMP_IMM(BPF_JNE, BF_REG_1, flags, 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
                   BPF_JMP_IMM(BPF_JEQ, BF_REG_1, flags, 0));
        break;
    case BF_MATCHER_ANY:
        EMIT(program, BPF_ALU32_IMM(BPF_AND, BPF_REG_1, flags));
        EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
                   BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));
        break;
    case BF_MATCHER_ALL:
        EMIT(program, BPF_ALU32_IMM(BPF_AND, BPF_REG_1, flags));
        EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
                   BPF_JMP_IMM(BPF_JNE, BPF_REG_1, flags, 0));
        break;
    default:
        return bf_err_code(-EINVAL, "unsupported matcher for tcp.flags: %s",
                           bf_matcher_op_to_str(matcher->op));
    }

    return 0;
}

int bf_matcher_generate_tcp(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_NEXT_RULE,
               BPF_JMP_IMM(BPF_JNE, BF_REG_1, IPPROTO_TCP, 0));

    switch (matcher->type) {
    case BF_MATCHER_TCP_SPORT:
    case BF_MATCHER_TCP_DPORT:
        r = _bf_matcher_generate_tcp_port(program, matcher);
        break;
    case BF_MATCHER_TCP_FLAGS:
        r = _bf_matcher_generate_tcp_flags(program, matcher);
        break;
    default:
        return bf_err_code(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    return r;
}
