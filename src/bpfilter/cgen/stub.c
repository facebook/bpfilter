/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/stub.h"

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h> // NOLINT
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <endian.h>
#include <stddef.h>

#include "bpfilter/cgen/fixup.h"
#include "bpfilter/cgen/jmp.h"
#include "bpfilter/cgen/printer.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/swich.h"
#include "core/flavor.h"
#include "core/helper.h"
#include "core/opts.h"
#include "core/verdict.h"

#include "external/filter.h"

/**
 * Generate stub to create a dynptr.
 *
 * @param program Program to generate the stub for. Must not be NULL.
 * @param arg_reg Register where the first argument to the dynptr creation
 *        function is located (SKB or xdp_md structure).
 * @param kfunc Name of the kfunc to use to create the dynamic pointer.
 * @return 0 on success, or negative errno value on error.
 */
static int _bf_stub_make_ctx_dynptr(struct bf_program *program, int arg_reg,
                                    const char *kfunc)
{
    bf_assert(program && kfunc);

    // Call bpf_dynptr_from_xxx()
    if (arg_reg != BPF_REG_1)
        EMIT(program, BPF_MOV64_IMM(BPF_REG_1, arg_reg));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(dynptr)));
    EMIT_KFUNC_CALL(program, kfunc);

    // If the function call failed, quit the program
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV32_IMM(BPF_REG_1, program->num_counters - 1));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(pkt_size)));
        EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);

        if (bf_opts_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create a new dynamic pointer");

        EMIT(program,
             BPF_MOV64_IMM(BPF_REG_0, program->runtime.ops->get_verdict(
                                          BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    return 0;
}

int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, int md_reg)
{
    bf_assert(program);

    return _bf_stub_make_ctx_dynptr(program, md_reg, "bpf_dynptr_from_xdp");
}

int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, int skb_reg)
{
    bf_assert(program);

    return _bf_stub_make_ctx_dynptr(program, skb_reg, "bpf_dynptr_from_skb");
}

int bf_stub_parse_l2_ethhdr(struct bf_program *program)
{
    bf_assert(program);

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_2, 0));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l2_raw)));
    EMIT(program, BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ethhdr)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV32_IMM(BPF_REG_1, program->num_counters - 1));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(pkt_size)));
        EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);

        if (bf_opts_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L2 dynamic pointer slice");

        EMIT(program,
             BPF_MOV64_IMM(BPF_REG_0, program->runtime.ops->get_verdict(
                                          BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L2 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l2_hdr)));

    // Store the L3 protocol ID in r7
    EMIT(program, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0,
                              offsetof(struct ethhdr, h_proto)));

    // Set bf_program_context.l3_offset
    EMIT(program, BPF_ST_MEM(BPF_W, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset),
                             sizeof(struct ethhdr)));

    return 0;
}

int bf_stub_parse_l3_hdr(struct bf_program *program)
{
    _cleanup_bf_jmpctx_ struct bf_jmpctx _;
    int r;

    bf_assert(program);

    /* Store the size of the L3 protocol header in r4, depending on the protocol
     * ID stored in r7. If the protocol is not supported, we store 0 into r7
     * and we skip the instructions below. */
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_7);

        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct iphdr)));
        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct ipv6hdr)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_7, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_7, 0, 0));

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(l3_offset)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l3_raw)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV32_IMM(BPF_REG_1, program->num_counters - 1));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(pkt_size)));
        EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);

        if (bf_opts_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L3 dynamic pointer slice");

        EMIT(program,
             BPF_MOV64_IMM(BPF_REG_0, program->runtime.ops->get_verdict(
                                          BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L3 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l3_hdr)));

    /* Unsupported L3 protocols have been filtered out at the beginning of this
     * function and would jump over the block below, so there is no need to
     * worry about them here. */
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_7);

        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                          BPF_LDX_MEM(BPF_B, BPF_REG_1, BPF_REG_0, 0),
                          BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 0x0f),
                          BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 2),
                          BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10,
                                      BF_PROG_CTX_OFF(l3_offset)),
                          BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
                          BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                      BF_PROG_CTX_OFF(l4_offset)),
                          BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_0,
                                      offsetof(struct iphdr, protocol)));
        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                          BPF_MOV64_IMM(BPF_REG_1, sizeof(struct ipv6hdr)),
                          BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10,
                                      BF_PROG_CTX_OFF(l3_offset)),
                          BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_2),
                          BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1,
                                      BF_PROG_CTX_OFF(l4_offset)),
                          BPF_LDX_MEM(BPF_B, BPF_REG_8, BPF_REG_0,
                                      offsetof(struct ipv6hdr, nexthdr)));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    return 0;
}

int bf_stub_parse_l4_hdr(struct bf_program *program)
{
    _cleanup_bf_jmpctx_ struct bf_jmpctx _;
    int r;

    bf_assert(program);

    /* Parse the L4 protocol and handle unuspported protocol, similarly to
     * bf_stub_parse_l3_hdr() above. */
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BPF_REG_8);

        EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct tcphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMP,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct udphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMPV6,
                          BPF_MOV64_IMM(BPF_REG_4, sizeof(struct icmp6hdr)));
        EMIT_SWICH_DEFAULT(&swich, BPF_MOV64_IMM(BPF_REG_8, 0));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }
    _ = bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0));

    // Call bpf_dynptr_slice()
    EMIT(program, BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BF_PROG_CTX_OFF(dynptr)));
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, BF_PROG_CTX_OFF(l4_offset)));
    EMIT(program, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, BF_PROG_CTX_OFF(l4_raw)));
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If the function call failed, quit the program
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 0));

        // Update the error counter
        EMIT(program, BPF_MOV32_IMM(BPF_REG_1, program->num_counters - 1));
        EMIT(program, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10,
                                  BF_PROG_CTX_OFF(pkt_size)));
        EMIT_FIXUP_CALL(program, BF_FIXUP_FUNC_UPDATE_COUNTERS);

        if (bf_opts_is_verbose(BF_VERBOSE_BPF))
            EMIT_PRINT(program, "failed to create L4 dynamic pointer slice");

        EMIT(program,
             BPF_MOV64_IMM(BPF_REG_0, program->runtime.ops->get_verdict(
                                          BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Store the L4 header address into the runtime context
    EMIT(program,
         BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, BF_PROG_CTX_OFF(l4_hdr)));

    return 0;
}
