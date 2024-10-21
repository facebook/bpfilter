/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/udp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/udp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "core/logger.h"
#include "core/matcher.h"

#include "external/filter.h"

static int _bf_matcher_generate_udp_port(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    uint16_t *port = (uint16_t *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_UDP_SPORT ?
                        offsetof(struct udphdr, source) :
                        offsetof(struct udphdr, dest);

    EMIT(program, BPF_LDX_MEM(BPF_H, BF_REG_4, BF_REG_L4, offset));

    switch (matcher->op) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BF_REG_4, htobe16(*port), 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, htobe16(*port), 0));
        break;
    case BF_MATCHER_RANGE:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JLT, BF_REG_4, htobe16(port[0]), 0));
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JGT, BF_REG_4, htobe16(port[1]), 0));
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher operator '%s' (%d)",
                        bf_matcher_op_to_str(matcher->op), matcher->op);
    }

    return 0;
}

int bf_matcher_generate_udp(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BF_REG_1, htobe16(IPPROTO_UDP), 0));

    switch (matcher->type) {
    case BF_MATCHER_UDP_SPORT:
    case BF_MATCHER_UDP_DPORT:
        r = _bf_matcher_generate_udp_port(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    return r;
}
