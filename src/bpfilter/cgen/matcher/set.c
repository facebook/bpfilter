/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/matcher/set.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/swich.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/matcher.h"

#include "external/filter.h"

int _bf_matcher_generate_set_ip6port(struct bf_program *program,
                                     const struct bf_matcher *matcher)
{
    _clean_bf_swich_ struct bf_swich swich;
    uint32_t set_id;
    int r;

    bf_assert(program);
    bf_assert(matcher);

    set_id = *(uint32_t *)matcher->payload;

    // Ensure IPv6, then load the header address into r6
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));

    // Get the source port into r2. If l4_proto is not UDP or TCP, jump to the next rule
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l4_hdr)));
    swich = bf_swich_get(program, BPF_REG_8);
    EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                      BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_6,
                                  offsetof(struct tcphdr, source)));
    EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                      BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_6,
                                  offsetof(struct udphdr, source)));
    EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_3, 0));
    r = bf_swich_generate(&swich);
    if (r)
        return bf_err_r(r, "failed to generate swich for meta.(s|d)port");
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_3, 0, 0));

    // Copy the source IPv6 address into r1 and r2
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
                              offsetof(struct ipv6hdr, saddr)));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
                              offsetof(struct ipv6hdr, saddr) + 8));

    //  Prepare the key
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(8)));
    EMIT(program,
         BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_3, BF_PROG_SCR_OFF(16)));

    // Call bpf_map_lookup_elem(r1=map_fd, r2=key_addr)
    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1, set_id);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // Key not found? Jump to the next rule
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

    return 0;
}

int _bf_matcher_generate_set_ip6(struct bf_program *program,
                                 const struct bf_matcher *matcher)
{
    uint32_t set_id;

    bf_assert(program && matcher);

    set_id = *(uint32_t *)matcher->payload;

    // Ensure IPv6, then loader the header address into r6
    EMIT_FIXUP_JMP_NEXT_RULE(
        program, BPF_JMP_IMM(BPF_JNE, BPF_REG_7, htobe16(ETH_P_IPV6), 0));
    EMIT(program,
         BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, BF_PROG_CTX_OFF(l3_hdr)));

    // Copy the source IPv6 address into r1 and r2
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6,
                              offsetof(struct ipv6hdr, saddr)));
    EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6,
                              offsetof(struct ipv6hdr, saddr) + 8));

    //  Prepare the key
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, BF_PROG_SCR_OFF(0)));
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, BF_PROG_SCR_OFF(8)));

    // Call bpf_map_lookup_elem(r1=map_fd, r2=key_addr)
    EMIT_LOAD_SET_FD_FIXUP(program, BPF_REG_1, set_id);
    EMIT(program, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, BF_PROG_SCR_OFF(0)));
    EMIT(program, BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem));

    // Key not found? Jump to the next rule
    EMIT_FIXUP_JMP_NEXT_RULE(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

    return 0;
}

int bf_matcher_generate_set(struct bf_program *program,
                            const struct bf_matcher *matcher)
{
    int r;

    switch (matcher->type) {
    case BF_MATCHER_SET_SRCIP6PORT:
        r = _bf_matcher_generate_set_ip6port(program, matcher);
        break;
    case BF_MATCHER_SET_SRCIP6:
        r = _bf_matcher_generate_set_ip6(program, matcher);
        break;
    default:
        return bf_err_r(-EINVAL, "unknown matcher type %d", matcher->type);
    };

    if (r)
        return r;

    return 0;
}
