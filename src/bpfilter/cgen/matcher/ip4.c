/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/ip4.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/program.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/matcher.h"
#include "core/runtime.h"

#include "external/filter.h"

static int _bf_matcher_generate_ip4_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    bf_assert(program && matcher);

    uint32_t *addr = (uint32_t *)bf_matcher_payload(matcher);
    size_t offset = bf_matcher_type(matcher) == BF_MATCHER_IP4_SADDR ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_2, *addr));

    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_REG(bf_matcher_op(matcher) == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                    BPF_REG_1, BPF_REG_2, 0));

    return 0;
}

static int _bf_matcher_generate_ip4_proto(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    bf_assert(program && matcher);

    uint8_t proto = *(uint8_t *)bf_matcher_payload(matcher);

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6,
                              offsetof(struct iphdr, protocol)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(bf_matcher_op(matcher) == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                    BPF_REG_1, proto, 0));

    return 0;
}

static void _bf_ip4_prefix_to_mask(uint32_t prefixlen, uint8_t *mask)
{
    bf_assert(mask);

    memset(mask, 0x00, 4);

    memset(mask, 0xff, prefixlen / 8);
    if (prefixlen % 8)
        mask[prefixlen / 8] = 0xff << (8 - prefixlen % 8) & 0xff;
}

static int _bf_matcher_generate_ip4_net(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    bf_assert(program && matcher);

    uint32_t mask;
    struct bf_ip4_lpm_key *addr =
        (struct bf_ip4_lpm_key *)bf_matcher_payload(matcher);
    size_t offset = bf_matcher_type(matcher) == BF_MATCHER_IP4_SNET ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    _bf_ip4_prefix_to_mask(addr->prefixlen, (void *)&mask);

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_MOV32_IMM(BPF_REG_2, addr->data));

    if (mask != ~0U) {
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, mask));
        EMIT(program, BPF_ALU32_REG(BPF_AND, BPF_REG_1, BPF_REG_3));
        EMIT(program, BPF_ALU32_REG(BPF_AND, BPF_REG_2, BPF_REG_3));
    }

    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_REG(bf_matcher_op(matcher) == BF_MATCHER_EQ ? BPF_JNE : BPF_JEQ,
                    BPF_REG_1, BPF_REG_2, 0));

    return 0;
}

int bf_matcher_generate_ip4(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    bf_assert(program && matcher);

    int r;

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));

    switch (bf_matcher_type(matcher)) {
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_DADDR:
        r = _bf_matcher_generate_ip4_addr(program, matcher);
        break;
    case BF_MATCHER_IP4_PROTO:
        r = _bf_matcher_generate_ip4_proto(program, matcher);
        break;
    case BF_MATCHER_IP4_SNET:
    case BF_MATCHER_IP4_DNET:
        r = _bf_matcher_generate_ip4_net(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_type(matcher));
    };

    if (r)
        return r;

    return 0;
}
