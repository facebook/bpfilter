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

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <bpfilter/logger.h>
#include <bpfilter/matcher.h>

#include "cgen/jmp.h"
#include "cgen/program.h"
#include "filter.h"

#define _bf_make32(a, b, c, d)                                                 \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) |    \
     (uint32_t)(d))
#define _BF_MASK_LAST_BYTE 15
#define BF_IPV6_EH_HOPOPTS(x) ((x) << 0)
#define BF_IPV6_EH_ROUTING(x) ((x) << 1)
#define BF_IPV6_EH_FRAGMENT(x) ((x) << 2)
#define BF_IPV6_EH_AH(x) ((x) << 3)
#define BF_IPV6_EH_DSTOPTS(x) ((x) << 4)
#define BF_IPV6_EH_MH(x) ((x) << 5)

static int _bf_matcher_generate_ip6_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    struct bf_jmpctx j0, j1;
    uint8_t *addr = (uint8_t *)bf_matcher_payload(matcher);
    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_IP6_SADDR ?
                        offsetof(struct ipv6hdr, saddr) :
                        offsetof(struct ipv6hdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));

    if (bf_matcher_get_op(matcher) == BF_MATCHER_EQ) {
        /* If we want to match an IP, both addr[0] and addr[1]
         * must match the packet, otherwise we jump to the next rule. */
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[7], addr[6],
                                                          addr[5], addr[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[3], addr[2],
                                                          addr[1], addr[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[15], addr[14],
                                                          addr[13], addr[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[11], addr[10],
                                                          addr[9], addr[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    } else {
        /* If we want to *not* match an IP, none of addr[0] and
         * addr[1] should match the packet, otherwise we jump to the
         * next rule. */
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[7], addr[6],
                                                          addr[5], addr[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[3], addr[2],
                                                          addr[1], addr[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        /* Branching:
         * - addr[0] matches the address' 64 MSB: continue to compare
         *   the address' 64 LSB.
         * - addr[0] doesn't matches the address' 64 MSB: jump to the
         *   end of the matcher to continue the processing of the current rule.
         *   This matcher matched. */
        j0 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr[15], addr[14],
                                                          addr[13], addr[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr[11], addr[10],
                                                          addr[9], addr[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        /* Branching:
         * - addr[1] matches the address' 64 LSB: addr matches the
         *   packet's address, meaning the matcher doesn't match. Jump to the
         *   next rule.
         * - addr[1] doesn't matches the address' 64 LSB: the matcher
         *   matched: addr is not equal to the packet's address. Continue
         *   processing with the next matcher. */
        j1 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        // j0 and j1 should jump here if they can't match the packet's IP.
        bf_jmpctx_cleanup(&j0);
        bf_jmpctx_cleanup(&j1);
    }

    return 0;
}

static void _bf_ip6_prefix_to_mask(uint32_t prefixlen, uint8_t *mask)
{
    bf_assert(mask);

    memset(mask, 0x00, 16);

    memset(mask, 0xff, prefixlen / 8);
    if (prefixlen % 8)
        mask[prefixlen / 8] = 0xff << (8 - prefixlen % 8) & 0xff;
}

static int _bf_matcher_generate_ip6_net(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    uint8_t mask[16];
    struct bf_jmpctx j0, j1;
    const struct bf_ip6_lpm_key *addr = bf_matcher_payload(matcher);
    size_t offset = bf_matcher_get_type(matcher) == BF_MATCHER_IP6_SNET ?
                        offsetof(struct ipv6hdr, saddr) :
                        offsetof(struct ipv6hdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));

    _bf_ip6_prefix_to_mask(addr->prefixlen, mask);

    if (mask[_BF_MASK_LAST_BYTE] != (uint8_t)~0) {
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(mask[7], mask[6],
                                                          mask[5], mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(mask[3], mask[2],
                                                          mask[1], mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_1, BPF_REG_3));

        EMIT(program, BPF_MOV32_IMM(BPF_REG_3, _bf_make32(mask[15], mask[14],
                                                          mask[13], mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4, _bf_make32(mask[11], mask[10],
                                                          mask[9], mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_2, BPF_REG_3));
    }

    if (bf_matcher_get_op(matcher) == BF_MATCHER_EQ) {
        /* If we want to match an IP, both addr->data[0] and addr->data[1]
         * must match the packet, otherwise we jump to the next rule. */
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr->data[7] & mask[7],
                                                 addr->data[6] & mask[6],
                                                 addr->data[5] & mask[5],
                                                 addr->data[4] & mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr->data[3] & mask[3],
                                                 addr->data[2] & mask[2],
                                                 addr->data[1] & mask[1],
                                                 addr->data[0] & mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr->data[15] & mask[15],
                                                 addr->data[14] & mask[14],
                                                 addr->data[13] & mask[13],
                                                 addr->data[12] & mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr->data[11] & mask[11],
                                                 addr->data[10] & mask[10],
                                                 addr->data[9] & mask[9],
                                                 addr->data[8] & mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    } else {
        /* If we want to *not* match an IP, none of addr->data[0] and
         * addr->data[1] should match the packet, otherwise we jump to the
         * next rule. */
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr->data[7] & mask[7],
                                                 addr->data[6] & mask[6],
                                                 addr->data[5] & mask[5],
                                                 addr->data[4] & mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr->data[3] & mask[3],
                                                 addr->data[2] & mask[2],
                                                 addr->data[1] & mask[1],
                                                 addr->data[0] & mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        /* Branching:
         * - addr->data[0] matches the address' 64 MSB: continue to compare
         *   the address' 64 LSB.
         * - addr->data[0] doesn't matches the address' 64 MSB: jump to the
         *   end of the matcher to continue the processing of the current rule.
         *   This matcher matched. */
        j0 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3, _bf_make32(addr->data[15] & mask[15],
                                                 addr->data[14] & mask[14],
                                                 addr->data[13] & mask[13],
                                                 addr->data[12] & mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_4, _bf_make32(addr->data[11] & mask[11],
                                                 addr->data[10] & mask[10],
                                                 addr->data[9] & mask[9],
                                                 addr->data[8] & mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        /* Branching:
         * - addr->data[1] matches the address' 64 LSB: addr->data matches the
         *   packet's address, meaning the matcher doesn't match. Jump to the
         *   next rule.
         * - addr->data[1] doesn't matches the address' 64 LSB: the matcher
         *   matched: addr->data is not equal to the packet's address. Continue
         *   processing with the next matcher. */
        j1 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        // j0 and j1 should jump here if they can't match the packet's IP.
        bf_jmpctx_cleanup(&j0);
        bf_jmpctx_cleanup(&j1);
    }

    return 0;
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
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d",
                        bf_matcher_get_type(matcher));
    };

    return r;
}
