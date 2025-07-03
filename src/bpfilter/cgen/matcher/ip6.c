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
#include "core/logger.h"
#include "core/matcher.h"
#include "core/set.h"

#include "external/filter.h"

#define _bf_make32(a, b, c, d)                                                 \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) |    \
     (uint32_t)(d))
#define _BF_MASK_LAST_BYTE 15

static int _bf_matcher_generate_ip6_addr(struct bf_program *program,
                                         const struct bf_matcher *matcher)
{
    struct bf_jmpctx j0, j1;
    struct bf_matcher_ip6_addr *addr = (void *)&matcher->payload;
    size_t offset = matcher->type == BF_MATCHER_IP6_SADDR ?
                        offsetof(struct ipv6hdr, saddr) :
                        offsetof(struct ipv6hdr, daddr);

    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6, offset));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));

    if (addr->mask[_BF_MASK_LAST_BYTE] != (uint8_t)~0) {
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3,
                                    _bf_make32(addr->mask[7], addr->mask[6],
                                               addr->mask[5], addr->mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4,
                                    _bf_make32(addr->mask[3], addr->mask[2],
                                               addr->mask[1], addr->mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_1, BPF_REG_3));

        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3,
                           _bf_make32(addr->mask[15], addr->mask[14],
                                      addr->mask[13], addr->mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4,
                                    _bf_make32(addr->mask[11], addr->mask[10],
                                               addr->mask[9], addr->mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT(program, BPF_ALU64_REG(BPF_AND, BPF_REG_2, BPF_REG_3));
    }

    if (matcher->op == BF_MATCHER_EQ) {
        /* If we want to match an IP, both addr->addr[0] and addr->addr[1]
         * must match the packet, otherwise we jump to the next rule. */
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3,
                                    _bf_make32(addr->addr[7] & addr->mask[7],
                                               addr->addr[6] & addr->mask[6],
                                               addr->addr[5] & addr->mask[5],
                                               addr->addr[4] & addr->mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4,
                                    _bf_make32(addr->addr[3] & addr->mask[3],
                                               addr->addr[2] & addr->mask[2],
                                               addr->addr[1] & addr->mask[1],
                                               addr->addr[0] & addr->mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3,
                           _bf_make32(addr->addr[15] & addr->mask[15],
                                      addr->addr[14] & addr->mask[14],
                                      addr->addr[13] & addr->mask[13],
                                      addr->addr[12] & addr->mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4,
                                    _bf_make32(addr->addr[11] & addr->mask[11],
                                               addr->addr[10] & addr->mask[10],
                                               addr->addr[9] & addr->mask[9],
                                               addr->addr[8] & addr->mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));
        EMIT_FIXUP_JMP_NEXT_RULE(program,
                                 BPF_JMP_REG(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    } else {
        /* If we want to *not* match an IP, none of addr->addr[0] and
         * addr->addr[1] should match the packet, otherwise we jump to the
         * next rule. */
        EMIT(program, BPF_MOV32_IMM(BPF_REG_3,
                                    _bf_make32(addr->addr[7] & addr->mask[7],
                                               addr->addr[6] & addr->mask[6],
                                               addr->addr[5] & addr->mask[5],
                                               addr->addr[4] & addr->mask[4])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4,
                                    _bf_make32(addr->addr[3] & addr->mask[3],
                                               addr->addr[2] & addr->mask[2],
                                               addr->addr[1] & addr->mask[1],
                                               addr->addr[0] & addr->mask[0])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        /* Branching:
         * - addr->addr[0] matches the address' 64 MSB: continue to compare
         *   the address' 64 LSB.
         * - addr->addr[0] doesn't matches the address' 64 MSB: jump to the
         *   end of the matcher to continue the processing of the current rule.
         *   This matcher matched. */
        j0 = bf_jmpctx_get(program,
                           BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, 0));

        EMIT(program,
             BPF_MOV32_IMM(BPF_REG_3,
                           _bf_make32(addr->addr[15] & addr->mask[15],
                                      addr->addr[14] & addr->mask[14],
                                      addr->addr[13] & addr->mask[13],
                                      addr->addr[12] & addr->mask[12])));
        EMIT(program, BPF_ALU64_IMM(BPF_LSH, BPF_REG_3, 32));
        EMIT(program, BPF_MOV32_IMM(BPF_REG_4,
                                    _bf_make32(addr->addr[11] & addr->mask[11],
                                               addr->addr[10] & addr->mask[10],
                                               addr->addr[9] & addr->mask[9],
                                               addr->addr[8] & addr->mask[8])));
        EMIT(program, BPF_ALU64_REG(BPF_OR, BPF_REG_3, BPF_REG_4));

        /* Branching:
         * - addr->addr[1] matches the address' 64 LSB: addr->addr matches the
         *   packet's address, meaning the matcher doesn't match. Jump to the
         *   next rule.
         * - addr->addr[1] doesn't matches the address' 64 LSB: the matcher
         *   matched: addr->addr is not equal to the packet's address. Continue
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

static int _bf_matcher_generate_ip6_net(struct bf_program *program,
                                        const struct bf_matcher *matcher)
{
    uint32_t set_id;
    struct bf_set *set;
    int16_t offset;

    bf_assert(program && matcher);

    set_id = *(uint32_t *)matcher->payload;
    set = bf_list_get_at(&program->runtime.chain->sets, set_id);
    if (!set)
        return bf_err_r(-ENOENT, "set #%d not found", set_id);

    switch (set->type) {
    case BF_SET_IP6_SUBNET:
        // Copy bf_ip6_lpm_key entries starting at scratch offset 4, so the
        // 64-bits copies for the address will be aligned
        offset = matcher->type == BF_MATCHER_IP6_SNET ?
                     offsetof(struct ipv6hdr, saddr) :
                     offsetof(struct ipv6hdr, daddr);
        EMIT(program, BPF_MOV64_IMM(BPF_REG_3, 128));
        EMIT(program,
             BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, BF_PROG_SCR_OFF(4)));

        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset));
        EMIT(program,
             BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(8)));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offset + 8));
        EMIT(program,
             BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(16)));
        break;
    default:
        return bf_err_r(-EINVAL, "unsupported set type: %s",
                        bf_set_type_to_str(set->type));
    }

    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1, set_id);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(4)));

    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // Jump to the next rule if map_lookup_elem returned 0
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

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

    switch (matcher->type) {
    case BF_MATCHER_IP6_SADDR:
    case BF_MATCHER_IP6_DADDR:
        r = _bf_matcher_generate_ip6_addr(program, matcher);
        break;
    case BF_MATCHER_IP6_SNET:
    case BF_MATCHER_IP6_DNET:
        r = _bf_matcher_generate_ip6_net(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    return r;
}
