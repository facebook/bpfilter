/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <errno.h>

#include "bpfilter/cgen/program.h"
#include "core/matcher.h"

static int _bf_matcher_generate_icmp_fields(struct bf_program *program,
                                            const struct bf_matcher *matcher)
{
    const uint8_t value = matcher->payload[0];
    size_t offset = matcher->type == BF_MATCHER_ICMP_TYPE ?
                        offsetof(struct icmphdr, type) :
                        offsetof(struct icmphdr, code);

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, offset));

    switch (matcher->op) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, value, 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, value, 0));
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher operator '%s' (%d)",
                        bf_matcher_op_to_str(matcher->op), matcher->op);
    }

    return 0;
}

int bf_matcher_generate_icmp(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    int r;

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(BPF_JNE, BPF_REG_8, IPPROTO_ICMP, 0));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));

    switch (matcher->type) {
    case BF_MATCHER_ICMP_TYPE:
    case BF_MATCHER_ICMP_CODE:
        r = _bf_matcher_generate_icmp_fields(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    return r;
}
