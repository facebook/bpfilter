/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/matcher/ip6.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>

#include <assert.h>
#include <endian.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/matcher/cmp.h"
#include "cgen/program.h"
#include "filter.h"

#define BF_IPV6_EH_HOPOPTS(x) ((x) << 0)
#define BF_IPV6_EH_ROUTING(x) ((x) << 1)
#define BF_IPV6_EH_FRAGMENT(x) ((x) << 2)
#define BF_IPV6_EH_AH(x) ((x) << 3)
#define BF_IPV6_EH_DSTOPTS(x) ((x) << 4)
#define BF_IPV6_EH_MH(x) ((x) << 5)

static int _bf_matcher_generate_ip6_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_IP6_SADDR ?
                        offsetof(struct ipv6hdr, saddr) :
                        offsetof(struct ipv6hdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));

    return bf_cmp_value(program, bf_matcher_get_op(matcher),
                        bf_matcher_payload(matcher), 16, BPF_REG_1);
}

static int _bf_matcher_generate_ip6_net(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    const struct bf_ip6_lpm_key *addr = bf_matcher_payload(matcher);
    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_IP6_SNET ?
                        offsetof(struct ipv6hdr, saddr) :
                        offsetof(struct ipv6hdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));

    return bf_cmp_masked_value(program, bf_matcher_get_op(matcher), addr->data,
                               addr->prefixlen, 16, BPF_REG_1);
}

static int _bf_matcher_generate_ip6_nexthdr(struct bf_program *program,
                                            const struct bf_matcher *matcher)
{
    const uint8_t ehdr = *(uint8_t *)bf_matcher_payload(matcher);
    uint8_t eh_mask;

    if ((bf_matcher_get_op(matcher) != BF_MATCHER_EQ) &&
        (bf_matcher_get_op(matcher) != BF_MATCHER_NE))
        return -EINVAL;

    switch (ehdr) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
    case IPPROTO_FRAGMENT:
    case IPPROTO_AH:
    case IPPROTO_MH:
        eh_mask = (BF_IPV6_EH_HOPOPTS(ehdr == IPPROTO_HOPOPTS) |
                   BF_IPV6_EH_ROUTING(ehdr == IPPROTO_ROUTING) |
                   BF_IPV6_EH_FRAGMENT(ehdr == IPPROTO_FRAGMENT) |
                   BF_IPV6_EH_AH(ehdr == IPPROTO_AH) |
                   BF_IPV6_EH_DSTOPTS(ehdr == IPPROTO_DSTOPTS) |
                   BF_IPV6_EH_MH(ehdr == IPPROTO_MH));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10,
                                  BF_PROG_CTX_OFF(ipv6_eh)));
        EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, eh_mask));
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM((bf_matcher_get_op(matcher) == BF_MATCHER_EQ) ?
                                     BPF_JEQ :
                                     BPF_JNE,
                                 BPF_REG_1, 0, 0));
        break;
    default:
        /* check l4 protocols using BPF_REG_8 */
        EMIT_FIXUP_JMP_NEXT_RULE(
            program, BPF_JMP_IMM((bf_matcher_get_op(matcher) == BF_MATCHER_EQ) ?
                                     BPF_JNE :
                                     BPF_JEQ,
                                 BPF_REG_8, ehdr, 0));
        break;
    }

    return 0;
}

static int _bf_matcher_generate_ip6_dscp(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    uint8_t dscp;

    assert(program);
    assert(matcher);

    dscp = *(uint8_t *)bf_matcher_payload(matcher);

    /* IPv6 DSCP (traffic class) spans bits 4-11 of the header:
     * Byte 0: version (4 bits) | dscp_high (4 bits)
     * Byte 1: dscp_low (4 bits) | flow_label_high (4 bits)
     * Load 2 bytes, mask with 0x0ff0, compare against dscp << 4. */

    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_1, BPF_REG_6, 0));
    EMIT(program, BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0ff0));

    EMIT_FIXUP_JMP_NEXT_RULE(
        program,
        BPF_JMP_IMM(bf_matcher_get_op(matcher) == BF_MATCHER_EQ ? BPF_JNE :
                                                                  BPF_JEQ,
                    BPF_REG_1, (uint16_t)dscp << 4, 0));

    return 0;
}

int bf_matcher_generate_ip6(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));

    switch (bf_matcher_get_type(matcher)) {
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_DADDR:
        r = _bf_matcher_generate_ip6_addr(program, matcher);
        break;
    case BF_MATCHER_IP6_SNET:
    case BF_MATCHER_IP6_DNET:
        r = _bf_matcher_generate_ip6_net(program, matcher);
        break;
    case BF_MATCHER_IP6_NEXTHDR:
        r = _bf_matcher_generate_ip6_nexthdr(program, matcher);
        break;
    case BF_MATCHER_IP6_DSCP:
        r = _bf_matcher_generate_ip6_dscp(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    };

    return r;
}
