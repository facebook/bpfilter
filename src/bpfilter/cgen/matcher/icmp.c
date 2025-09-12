/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

#include <errno.h>

#include "bpfilter/cgen/program.h"
#include "core/matcher.h"

static int _bf_matcher_generate_icmp_fields(struct bf_program *program,
                                            const struct bf_matcher *matcher,
                                            const size_t offset)
{
    const uint8_t value = *(uint8_t *)bf_matcher_payload(matcher);

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, offset));

    switch (bf_matcher_op(matcher)) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JNE, BPF_REG_1, value, 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, value, 0));
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher operator '%s' (%d)",
                        bf_matcher_op_to_str(bf_matcher_op(matcher)),
                        bf_matcher_op(matcher));
    }

    return 0;
}

static int _bf_matcher_generate_icmp6_fields(struct bf_program *program,
                                             const struct bf_matcher *matcher)
{
    size_t offset = bf_matcher_type(matcher) == BF_MATCHER_ICMPV6_TYPE ?
                        offsetof(struct icmp6hdr, icmp6_type) :
                        offsetof(struct icmp6hdr, icmp6_code);

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_8, IPPROTO_ICMPV6, 0));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));

    return _bf_matcher_generate_icmp_fields(program, matcher, offset);
}

static int _bf_matcher_generate_icmp4_fields(struct bf_program *program,
                                             const struct bf_matcher *matcher)
{
    size_t offset = bf_matcher_type(matcher) == BF_MATCHER_ICMP_TYPE ?
                        offsetof(struct icmphdr, type) :
                        offsetof(struct icmphdr, code);

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(BPF_JNE, BPF_REG_8, IPPROTO_ICMP, 0));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));

    return _bf_matcher_generate_icmp_fields(program, matcher, offset);
}

int bf_matcher_generate_icmp(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    int r;

    switch (bf_matcher_type(matcher)) {
    case BF_MATCHER_ICMP_TYPE:
    case BF_MATCHER_ICMP_CODE:
        r = _bf_matcher_generate_icmp4_fields(program, matcher);
        break;
    case BF_MATCHER_ICMPV6_TYPE:
    case BF_MATCHER_ICMPV6_CODE:
        r = _bf_matcher_generate_icmp6_fields(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_type(matcher));
    };

    return r;
}
