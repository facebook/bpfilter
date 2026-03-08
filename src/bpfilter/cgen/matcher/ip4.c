/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/ip4.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <assert.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>
#include <bpfilter/runtime.h>

#include "cgen/matcher/cmp.h"
#include "cgen/program.h"
#include "filter.h"

static int _bf_matcher_generate_ip4_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_IP4_SADDR ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offset));
    return bf_cmp_value(program, bf_matcher_get_op(matcher),
                        bf_matcher_payload(matcher), 4, BPF_REG_1);
}

static int _bf_matcher_generate_ip4_proto(struct bf_program *program,
                                          const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    EMIT(program, BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6,
                              offsetof(struct iphdr, protocol)));
    return bf_cmp_value(program, bf_matcher_get_op(matcher),
                        bf_matcher_payload(matcher), 1, BPF_REG_1);
}

static int _bf_matcher_generate_ip4_dscp(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    EMIT(program,
         BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_6, offsetof(struct iphdr, tos)));
    return bf_cmp_value(program, bf_matcher_get_op(matcher),
                        bf_matcher_payload(matcher), 1, BPF_REG_1);
}

static int _bf_matcher_generate_ip4_net(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    struct bf_ip4_lpm_key *addr =
        (struct bf_ip4_lpm_key *)bf_matcher_payload(matcher);
    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_IP4_SNET ?
                        offsetof(struct iphdr, saddr) :
                        offsetof(struct iphdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_6, offset));
    return bf_cmp_masked_value(program, bf_matcher_get_op(matcher), &addr->data,
                               addr->prefixlen, 4, BPF_REG_1);
}

int bf_matcher_generate_ip4(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    assert(program);
    assert(matcher);

    int r;

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IP), 0));

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_IP4_SADDR:
    case BF_MATCHER_IP4_DADDR:
        r = _bf_matcher_generate_ip4_addr(program, matcher);
        break;
    case BF_MATCHER_IP4_PROTO:
        r = _bf_matcher_generate_ip4_proto(program, matcher);
        break;
    case BF_MATCHER_IP4_DSCP:
        r = _bf_matcher_generate_ip4_dscp(program, matcher);
        break;
    case BF_MATCHER_IP4_SNET:
    case BF_MATCHER_IP4_DNET:
        r = _bf_matcher_generate_ip4_net(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    };

    if (r)
        return r;

    return 0;
}
