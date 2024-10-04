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

#include "bpfilter/cgen/jmp.h"
#include "bpfilter/cgen/printer.h"
#include "bpfilter/cgen/program.h"
#include "bpfilter/cgen/reg.h"
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
static int _bf_stub_make_ctx_dynptr(struct bf_program *program,
                                    enum bf_reg arg_reg, const char *kfunc)
{
    bf_assert(program);
    bf_assert(kfunc);

    // BF_ARG_1: address of the SKB or xdp_md structure.
    if (arg_reg != BF_ARG_1)
        EMIT(program, BPF_MOV64_IMM(BF_ARG_1, arg_reg));

    // BF_ARG_2: flags.
    EMIT(program, BPF_MOV64_IMM(BF_ARG_2, 0));

    // BF_ARG_3: address of the dynptr in the context
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(dynptr)));

    EMIT_KFUNC_CALL(program, kfunc);

    // Copy the return value to BF_REG_2.
    EMIT(program, BPF_MOV64_REG(BF_REG_2, BF_REG_RET));

    // If the function call failed, quit the program.
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_2, 0, 0));

        if (bf_opts_debug())
            EMIT_PRINT(program, "failed to create a new dynamic pointer");

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    return 0;
}

int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, enum bf_reg md_reg)
{
    bf_assert(program);

    return _bf_stub_make_ctx_dynptr(program, md_reg, "bpf_dynptr_from_xdp");
}

int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, enum bf_reg skb_reg)
{
    bf_assert(program);

    return _bf_stub_make_ctx_dynptr(program, skb_reg, "bpf_dynptr_from_skb");
}

int bf_stub_parse_l2_ethhdr(struct bf_program *program)
{
    bf_assert(program);

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_1, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_1, BF_PROG_CTX_OFF(dynptr)));

    // BF_ARG_2: offset
    EMIT(program, BPF_MOV64_IMM(BF_ARG_2, 0));

    // BF_ARG_3: pointer to the buffer to store L2 header.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(l2_raw)));

    // BF_ARG_4: size of the L2 header buffer.
    EMIT(program, BPF_MOV64_IMM(BF_ARG_4, sizeof(struct ethhdr)));

    // Create the slice, accept the packet if it fails.
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_RET, 0, 0));

        if (bf_opts_debug())
            EMIT_PRINT(program, "failed to create L2 dynamic pointer slice");

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Copy the L2 header pointer to BF_REG_L2.
    EMIT(program, BPF_MOV64_REG(BF_REG_L2, BF_REG_RET));

    // Set bf_program_context.l3_proto
    EMIT(program, BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_L2,
                              offsetof(struct ethhdr, h_proto)));
    EMIT(program,
         BPF_STX_MEM(BPF_H, BF_REG_CTX, BF_REG_1, BF_PROG_CTX_OFF(l3_proto)));

    // Set bf_program_context.l3_offset
    EMIT(program, BPF_ST_MEM(BPF_W, BF_REG_CTX, BF_PROG_CTX_OFF(l3_offset),
                             sizeof(struct ethhdr)));

    return 0;
}

int bf_stub_parse_l3_hdr(struct bf_program *program)
{
    int r;

    bf_assert(program);

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_1, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_1, BF_PROG_CTX_OFF(dynptr)));

    // BF_ARG_2: L3 header offset from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BF_ARG_2, BF_REG_CTX, BF_PROG_CTX_OFF(l3_offset)));

    // BF_ARG_3: pointer to the buffer.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(l3_raw)));

    // BF_ARG_4: size of the buffer
    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_ARG_4, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BF_ARG_4);

        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                          BPF_MOV64_IMM(BF_ARG_4, sizeof(struct iphdr)));
        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                          BPF_MOV64_IMM(BF_ARG_4, sizeof(struct ipv6hdr)));
        EMIT_SWICH_DEFAULT(
            &swich,
            BPF_MOV64_IMM(BF_REG_RET,
                          program->runtime.ops->get_verdict(BF_VERDICT_ACCEPT)),
            BPF_EXIT_INSN());

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    // Create the slice, accept the packet if it fails.
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_RET, 0, 0));

        if (bf_opts_debug())
            EMIT_PRINT(program, "failed to create L3 dynamic pointer slice");

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    EMIT(program, BPF_MOV64_REG(BF_REG_L3, BF_REG_RET));

    EMIT(program,
         BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_CTX, BF_PROG_CTX_OFF(l3_proto)));
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BF_REG_1);

        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IP),
                          BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_L3, 0),
                          BPF_ALU64_IMM(BPF_AND, BF_REG_1, 0x0f),
                          BPF_ALU64_IMM(BPF_LSH, BF_REG_1, 2),
                          BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_CTX,
                                      BF_PROG_CTX_OFF(l3_offset)),
                          BPF_ALU64_REG(BPF_ADD, BF_REG_1, BF_REG_2),
                          BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_1,
                                      BF_PROG_CTX_OFF(l4_offset)),
                          BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_L3,
                                      offsetof(struct iphdr, protocol)),
                          BPF_STX_MEM(BPF_B, BF_REG_CTX, BF_REG_1,
                                      BF_PROG_CTX_OFF(l4_proto)));
        EMIT_SWICH_OPTION(&swich, htobe16(ETH_P_IPV6),
                          BPF_MOV64_IMM(BF_REG_1, sizeof(struct ipv6hdr)),
                          BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_CTX,
                                      BF_PROG_CTX_OFF(l3_offset)),
                          BPF_ALU64_REG(BPF_ADD, BF_REG_1, BF_REG_2),
                          BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_1,
                                      BF_PROG_CTX_OFF(l4_offset)),
                          BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_L3,
                                      offsetof(struct ipv6hdr, nexthdr)),
                          BPF_STX_MEM(BPF_B, BF_REG_CTX, BF_REG_1,
                                      BF_PROG_CTX_OFF(l4_proto)));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    return 0;
}

int bf_stub_parse_l4_hdr(struct bf_program *program)
{
    int r;

    bf_assert(program);

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_1, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_1, BF_PROG_CTX_OFF(dynptr)));

    // BF_ARG_2: L4 header offset from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BF_ARG_2, BF_REG_CTX, BF_PROG_CTX_OFF(l4_offset)));

    // BF_ARG_3: pointer to the buffer.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(l4_raw)));

    // BF_ARG_4: size of the buffer.
    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_4, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));
    {
        _cleanup_bf_swich_ struct bf_swich swich =
            bf_swich_get(program, BF_ARG_4);

        EMIT_SWICH_OPTION(&swich, IPPROTO_TCP,
                          BPF_MOV64_IMM(BF_REG_4, sizeof(struct tcphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_UDP,
                          BPF_MOV64_IMM(BF_REG_4, sizeof(struct udphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMP,
                          BPF_MOV64_IMM(BF_REG_4, sizeof(struct udphdr)));
        EMIT_SWICH_OPTION(&swich, IPPROTO_ICMPV6,
                          BPF_MOV64_IMM(BF_REG_4, sizeof(struct icmp6hdr)));

        r = bf_swich_generate(&swich);
        if (r)
            return r;
    }

    // Create the slice, accept hte packet if it fails
    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_RET, 0, 0));

        if (bf_opts_debug())
            EMIT_PRINT(program, "failed to create L4 dynamic pointer slice");

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Copy the L3 header pointer to BF_REG_L3.
    EMIT(program, BPF_MOV64_REG(BF_REG_L4, BF_REG_RET));

    return 0;
}
