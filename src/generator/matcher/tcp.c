/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "generator/matcher/tcp.h"

#include <arpa/inet.h>

#include "core/logger.h"
#include "core/matcher.h"
#include "generator/fixup.h"
#include "generator/printer.h"
#include "generator/program.h"

// clang-format off
// Required because of conflicting definitions from glibc
#include <linux/in.h>
// clang-format on

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
                           BF_REG_4, htons(port), 0));

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
    default:
        return bf_err_code(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    return r;
}
