/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/udp.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/udp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/program.h"
#include "filter.h"

static int _bf_matcher_generate_udp_port(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    uint16_t *port = (uint16_t *)bf_matcher_payload(matcher);
    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_UDP_SPORT ?
                        offsetof(struct udphdr, source) :
                        offsetof(struct udphdr, dest);

    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6, offset));

    switch (bf_matcher_get_op(matcher)) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JNE, BPF_REG_1, *port, 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, *port, 0));
        break;
    case BF_MATCHER_RANGE:
        /* Convert the big-endian value stored in the packet into a
         * little-endian value for x86 and arm before comparing it to the
         * reference value. This is a JLT/JGT comparison, we need to have the
         * MSB where the machine expects then. */
        EMIT(program, BPF_BSWAP(BPF_REG_1, 16));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JLT, BPF_REG_1, port[0], 0));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_IMM(BPF_JGT, BPF_REG_1, port[1], 0));
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher operator '%s' (%d)",
                        bf_matcher_op_to_str(bf_matcher_get_op(matcher)),
                        bf_matcher_get_op(matcher));
    }

    return 0;
}

int bf_matcher_generate_udp(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT_FIXUP_JMP_NEXT_RULE(program,
                             BPF_JMP_IMM(BPF_JNE, BPF_REG_8, IPPROTO_UDP, 0));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_UDP_SPORT:
    case BF_MATCHER_UDP_DPORT:
        r = _bf_matcher_generate_udp_port(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    };

    return r;
}
