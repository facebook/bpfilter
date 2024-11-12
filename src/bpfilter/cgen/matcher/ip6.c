/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/ip6.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/jmp.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
#include "core/logger.h"
#include "core/matcher.h"

#include "external/filter.h"

#define _bf_make32(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))
#define _BF_MASK_LAST_BYTE 15

static int _bf_matcher_generate_ip6_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    struct bf_jmpctx j0, j1;
    struct bf_matcher_ip6_addr *addr = (void *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_IP6_SADDR ?
                        offsetof(struct ipv6hdr, saddr) :
                        offsetof(struct ipv6hdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_1, BF_REG_L3, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BF_REG_2, BF_REG_L3, offset + 8));

    if (addr->mask[_BF_MASK_LAST_BYTE] != (uint8_t)~0) {
        EMIT(program,
             BPF_MOV32_IMM(BF_REG_3, _bf_make32(addr->mask[7], addr->mask[6],
                                                addr->mask[5], addr->mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_3, 32));
        EMIT(program,
             BPF_MOV32_IMM(BF_REG_4, _bf_make32(addr->mask[3], addr->mask[2],
                                                addr->mask[1], addr->mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BF_REG_3, BF_REG_4));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BF_REG_1, BF_REG_3));

        EMIT(program,
             BPF_MOV32_IMM(BF_REG_3,
                           _bf_make32(addr->mask[15], addr->mask[14],
                                      addr->mask[13], addr->mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_3, 32));
        EMIT(program,
             BPF_MOV32_IMM(BF_REG_4, _bf_make32(addr->mask[11], addr->mask[10],
                                                addr->mask[9], addr->mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BF_REG_3, BF_REG_4));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BF_REG_2, BF_REG_3));
    }

    if (matcher->op == BF_MATCHER_EQ) {
        /* If we want to match an IP, both addr->addr[0] and addr->addr[1]
         * must match the packet, otherwise we jump to the next rule. */
        EMIT(program, BPF_MOV32_IMM(BF_REG_3,
                                    _bf_make32(addr->addr[7] & addr->mask[7],
                                               addr->addr[6] & addr->mask[6],
                                               addr->addr[5] & addr->mask[5],
                                               addr->addr[4] & addr->mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BF_REG_4,
                                    _bf_make32(addr->addr[3] & addr->mask[3],
                                               addr->addr[2] & addr->mask[2],
                                               addr->addr[1] & addr->mask[1],
                                               addr->addr[0] & addr->mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BF_REG_3, BF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BF_REG_1, BF_REG_3, 0));

        EMIT(program,
             BPF_MOV32_IMM(BF_REG_3,
                           _bf_make32(addr->addr[15] & addr->mask[15],
                                      addr->addr[14] & addr->mask[14],
                                      addr->addr[13] & addr->mask[13],
                                      addr->addr[12] & addr->mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BF_REG_4,
                                    _bf_make32(addr->addr[11] & addr->mask[11],
                                               addr->addr[10] & addr->mask[10],
                                               addr->addr[9] & addr->mask[9],
                                               addr->addr[8] & addr->mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BF_REG_3, BF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BF_REG_2, BF_REG_3, 0));
    } else {
        /* If we want to *not* match an IP, none of addr->addr[0] and
         * addr->addr[1] should match the packet, otherwise we jump to the
         * next rule. */
        EMIT(program, BPF_MOV32_IMM(BF_REG_3,
                                    _bf_make32(addr->addr[7] & addr->mask[7],
                                               addr->addr[6] & addr->mask[6],
                                               addr->addr[5] & addr->mask[5],
                                               addr->addr[4] & addr->mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BF_REG_4,
                                    _bf_make32(addr->addr[3] & addr->mask[3],
                                               addr->addr[2] & addr->mask[2],
                                               addr->addr[1] & addr->mask[1],
                                               addr->addr[0] & addr->mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BF_REG_3, BF_REG_4));

        /* Branching:
         * - addr->addr[0] matches the address' 64 MSB: continue to compare
         *   the address' 64 LSB.
         * - addr->addr[0] doesn't matches the address' 64 MSB: jump to the
         *   end of the matcher to continue the processing of the current rule.
         *   This matcher matched. */
        j0 =
            bf_jmpctx_get(program, BPF_JMP_REG(BPF_JNE, BF_REG_1, BF_REG_3, 0));

        EMIT(program,
             BPF_MOV32_IMM(BF_REG_3,
                           _bf_make32(addr->addr[15] & addr->mask[15],
                                      addr->addr[14] & addr->mask[14],
                                      addr->addr[13] & addr->mask[13],
                                      addr->addr[12] & addr->mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BF_REG_4,
                                    _bf_make32(addr->addr[11] & addr->mask[11],
                                               addr->addr[10] & addr->mask[10],
                                               addr->addr[9] & addr->mask[9],
                                               addr->addr[8] & addr->mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BF_REG_3, BF_REG_4));

        /* Branching:
         * - addr->addr[1] matches the address' 64 LSB: addr->addr matches the
         *   packet's address, meaning the matcher doesn't match. Jump to the
         *   next rule.
         * - addr->addr[1] doesn't matches the address' 64 LSB: the matcher
         *   matched: addr->addr is not equal to the packet's address. Continue
         *   processing with the next matcher. */
        j1 =
            bf_jmpctx_get(program, BPF_JMP_REG(BPF_JNE, BF_REG_2, BF_REG_3, 0));

        EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_A(0));

        // j0 and j1 should jump here if they can't match the packet's IP.
        bf_jmpctx_cleanup(&j0);
        bf_jmpctx_cleanup(&j1);
    }

    return 0;
}

int bf_matcher_generate_ip6(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BF_REG_1, htobe16(ETH_P_IPV6), 0));

    switch (matcher->type) {
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_DADDR:
        r = _bf_matcher_generate_ip6_addr(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    return r;
}
