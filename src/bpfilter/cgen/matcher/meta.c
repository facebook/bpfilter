/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/meta.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h> // NOLINT
#include <linux/tcp.h>
#include <linux/udp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "bpfilter/cgen/swich.h"
#include "core/logger.h"
#include "core/matcher.h"

#include "external/filter.h"

static int _bf_matcher_generate_meta_ifindex(struct bf_program *program,
                                             const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(ifindex)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(BPF_JNE, BF_REG_1, *(uint32_t *)&matcher->payload, 0));

    return 0;
}

static int _bf_matcher_generate_meta_l3_proto(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BF_REG_1,
                             htobe16(*(uint16_t *)&matcher->payload), 0));

    return 0;
}

static int _bf_matcher_generate_meta_l4_proto(struct bf_program *program,
                                              const struct bf_matcher *matcher)
{
    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(BPF_JNE, BF_REG_1, *(uint8_t *)&matcher->payload, 0));

    return 0;
}

static int _bf_matcher_generate_meta_port(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    _cleanup_bf_swich_ struct bf_swich swich;
    uint16_t *port = (uint16_t *)&matcher->payload;
    int r;

    // r1 = port to match, r2 = l4_proto
    EMIT(program, BPF_MOV64_IMM(BF_REG_1, 0));
    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_2, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));

    // Get the filtered port into r1
    swich = bf_swich_get(program, BF_REG_2);
    EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                      BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_L4,
                                  matcher->type == BF_MATCHER_META_SPORT ?
                                      offsetof(struct tcphdr, source) :
                                      offsetof(struct tcphdr, dest)));
    EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                      BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_L4,
                                  matcher->type == BF_MATCHER_META_SPORT ?
                                      offsetof(struct udphdr, source) :
                                      offsetof(struct udphdr, dest)));
    EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BF_REG_1, 0));

    r = bf_swich_generate(&swich);
    if (r)
        return bf_err_r(r, "failed to generate swich for meta.(s|d)port");

    // If r1 == 0: no TCP nor UDP header found, jump to the next rule
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_1, 0, 0));

    switch (matcher->op) {
    case BF_MATCHER_EQ:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JNE, BF_REG_1, htobe16(*port), 0));
        break;
    case BF_MATCHER_NE:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JEQ, BF_REG_1, htobe16(*port), 0));

        break;
    case BF_MATCHER_RANGE:
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JLT, BF_REG_1, htobe16(port[0]), 0));
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM(BPF_JGT, BF_REG_1, htobe16(port[1]), 0));
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher operator '%s' (%d)",
                        bf_matcher_op_to_str(matcher->op), matcher->op);
    }

    return 0;
}

int bf_matcher_generate_meta(struct bf_program *program,
                             const struct bf_matcher *matcher)
{
    int r;

    switch (matcher->type) {
    case BF_MATCHER_META_IFINDEX:
        r = _bf_matcher_generate_meta_ifindex(program, matcher);
        break;
    case BF_MATCHER_META_L3_PROTO:
        r = _bf_matcher_generate_meta_l3_proto(program, matcher);
        break;
    case BF_MATCHER_META_L4_PROTO:
        r = _bf_matcher_generate_meta_l4_proto(program, matcher);
        break;
    case BF_MATCHER_META_SPORT:
    case BF_MATCHER_META_DPORT:
        r = _bf_matcher_generate_meta_port(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    if (r)
        return r;

    return 0;
}
