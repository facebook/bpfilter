/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/meta.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/tcp.h>
#include <linux/udp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/program.h"
#include "cgen/swich.h"
#include "filter.h"

static int _bf_matcher_generate_meta_iface(struct bf_program *program,
                                           const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_10, BF_PROG_CTX_OFF(ifindex)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1,
                             *(uint32_t *)bf_matcher_payload(matcher), 0));

    return 0;
}

static int _bf_matcher_generate_meta_l3_proto(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(BPF_JNE, BPF_REG_7,
                    htobe16(*(uint16_t *)bf_matcher_payload(matcher)), 0));

    return 0;
}

static int _bf_matcher_generate_meta_l4_proto(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(bf_matcher_get_op(matcher) == BF_MATCHER_EQ ? BPF_JNE :
                                                                  BPF_JEQ,
                    BPF_REG_8, *(uint8_t *)bf_matcher_payload(matcher), 0));

    return 0;
}

static int
_bf_matcher_generate_meta_probability(struct bf_program *program,
                                      const struct bf_matcher *matcher)
{
    uint8_t proba = *(uint8_t *)bf_matcher_payload(matcher);

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JGT, BPF_REG_0,
                             (int)(UINT32_MAX * (proba / 100.0)), 0));

    return 0;
}

static int _bf_matcher_generate_meta_port(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    _clean_bf_swich_ struct bf_swich swich;
    uint16_t *port = (uint16_t *)bf_matcher_payload(matcher);
    int r;

    // Load L4 header address into r6
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));

    // Get the packet's port into r1
    swich = bf_swich_get(program, BPF_REG_8);
    EMIT_SWICH_OPTION(
        &swich, IPPROTO_TCP,
        BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6,
                    bf_matcher_get_type(matcher) == BF_MATCHER_META_SPORT ?
                        offsetof(struct tcphdr, source) :
                        offsetof(struct tcphdr, dest)));
    EMIT_SWICH_OPTION(
        &swich, IPPROTO_UDP,
        BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6,
                    bf_matcher_get_type(matcher) == BF_MATCHER_META_SPORT ?
                        offsetof(struct udphdr, source) :
                        offsetof(struct udphdr, dest)));
    EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_1, 0));

    r = bf_swich_generate(&swich);
    if (r)
        return bf_err_r(r, "failed to generate swich for meta.(s|d)port");

    // If r1 == 0: no TCP nor UDP header found, jump to the next rule
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0));

    switch (bf_matcher_get_op(matcher)) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BPF_REG_1, htobe16(*port), 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, htobe16(*port), 0));
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

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    int r;

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_META_IFACE:
        r = _bf_matcher_generate_meta_iface(program, matcher);
        break;
    case BF_MATCHER_META_L3_PROTO:
        r = _bf_matcher_generate_meta_l3_proto(program, matcher);
        break;
    case BF_MATCHER_META_L4_PROTO:
        r = _bf_matcher_generate_meta_l4_proto(program, matcher);
        break;
    case BF_MATCHER_META_PROBABILITY:
        r = _bf_matcher_generate_meta_probability(program, matcher);
        break;
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
        r = _bf_matcher_generate_meta_port(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    };

    if (r)
        return r;

    return 0;
}
