/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/stub.h"

#include <arpa/inet.h>

#include <linux/bpf.h>

#include "core/flavor.h"
#include "generator/jmp.h"
#include "generator/program.h"
#include "generator/reg.h"
#include "shared/helper.h"

#include "external/filter.h"

int bf_stub_memclear(struct bf_program *program, enum bf_reg addr_reg,
                     size_t size)
{
    bf_assert(program);
    bf_assert(!(size % 8));

    for (size_t i = 0; i < size; i += 8)
        EMIT(program, BPF_ST_MEM(BPF_DW, addr_reg, i, 0));

    return 0;
}

/**
 * @brief Generate stub to create a dynptr.
 *
 * @param program Program to generate the stub for. Must not be NULL.
 * @param arg_reg Register where the first argument to the dynptr creation
 *  function is located (SKB or xdp_md structure).
 * @param kfunc Name of the kfunc to use to create the dynamic pointer.
 * @return 0 on success, or negative errno value on error.
 */
static int _stub_make_ctx_dynptr(struct bf_program *program,
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

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    return 0;
}

int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, enum bf_reg md_reg)
{
    assert(program);

    return _stub_make_ctx_dynptr(program, md_reg, "bpf_dynptr_from_xdp");
}

int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, enum bf_reg skb_reg)
{
    assert(program);

    return _stub_make_ctx_dynptr(program, skb_reg, "bpf_dynptr_from_skb");
}

int bf_stub_get_l2_eth_hdr(struct bf_program *program)
{
    bf_assert(program);

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_1, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_1, BF_PROG_CTX_OFF(dynptr)));

    // BF_ARG_2: offset
    EMIT(program, BPF_MOV64_IMM(BF_ARG_2, 0));

    // BF_ARG_3: pointer to the buffer to store L2 header.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(l2raw)));

    // BF_ARG_4: size of the L2 header buffer.
    EMIT(program, BPF_MOV64_IMM(BF_ARG_4, sizeof(struct ethhdr)));

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // Copy the L2 header pointer to BF_REG_L2.
    EMIT(program, BPF_MOV64_REG(BF_REG_L2, BF_REG_RET));

    // If L2 was not found, quit the program.
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_L2, 0, 0));

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Load L2 ethertype
    EMIT(program, BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_L2,
                              offsetof(struct ethhdr, h_proto)));

    // If L3 is not IPv4, quit the program.
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ = bf_jmpctx_get(
            program, BPF_JMP_IMM(BPF_JEQ, BF_REG_1, ntohs(ETH_P_IP), 0));

        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Update L3 header offset.
    EMIT(program, BPF_ST_MEM(BPF_W, BF_REG_CTX, BF_PROG_CTX_OFF(l3_offset),
                             sizeof(struct ethhdr)));

    return 0;
}

int bf_stub_get_l3_ipv4_hdr(struct bf_program *program)
{
    bf_assert(program);

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_1, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_1, BF_PROG_CTX_OFF(dynptr)));

    // BF_ARG_2: L3 header offset from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BF_ARG_2, BF_REG_CTX, BF_PROG_CTX_OFF(l3_offset)));

    // BF_ARG_3: pointer to the buffer.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(l3raw)));

    // BF_ARG_4: size of the buffer
    EMIT(program, BPF_MOV64_IMM(BF_ARG_4, sizeof(struct iphdr)));

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // Copy the L3 header pointer to BF_REG_L3.
    EMIT(program, BPF_MOV64_REG(BF_REG_L3, BF_REG_RET));

    // If L3 was not found, quit the program.
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_L3, 0, 0));
        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    // Load ip.ihl into BF_REG_1
    EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_L3, 0));

    // Only keep the 4 IHL bits
    EMIT(program, BPF_ALU64_IMM(BPF_AND, BF_REG_1, 15));

    // Convert the number of words stored in ip.ihl into a number of bytes.
    EMIT(program, BPF_ALU64_IMM(BPF_LSH, BF_REG_1, 2));

    // Store the L3 offset in BF_REG_2
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BF_REG_2, BF_REG_CTX, BF_PROG_CTX_OFF(l3_offset)));

    // Add the L3 offset to the L4 offset
    EMIT(program, BPF_ALU64_REG(BPF_ADD, BF_REG_1, BF_REG_2));

    // Store the L4 header offset back into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_1, BF_PROG_CTX_OFF(l4_offset)));

    // Copy the L4 protocol into BF_REG_1
    EMIT(program, BPF_LDX_MEM(BPF_B, BF_REG_1, BF_REG_L3,
                              offsetof(struct iphdr, protocol)));

    // Store the L4 protocol into the context.
    EMIT(program,
         BPF_STX_MEM(BPF_B, BF_REG_CTX, BF_REG_1, BF_PROG_CTX_OFF(l4_proto)));

    return 0;
}

int bf_stub_get_l4_hdr(struct bf_program *program)
{
    bf_assert(program);

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_1, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_1, BF_PROG_CTX_OFF(dynptr)));

    // BF_ARG_2: L4 header offset from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_W, BF_ARG_2, BF_REG_CTX, BF_PROG_CTX_OFF(l4_offset)));

    // BF_ARG_3: pointer to the buffer.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(l4raw)));

    // Load L4 protocol from the context.
    EMIT(program,
         BPF_LDX_MEM(BPF_B, BF_REG_4, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));

    {
        // If L4 protocol is TCP.
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, IPPROTO_TCP, 3));

        // If L4 protocol is UDP.
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, IPPROTO_UDP, 4));

        // If L4 protocol is ICMP.
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, IPPROTO_ICMP, 5));

        // Protocol is not supported, skip slice request.
        EMIT(program, BPF_JMP_A(10));

        // If TCP
        EMIT(program, BPF_MOV64_IMM(BF_REG_4, sizeof(struct tcphdr)));
        EMIT(program, BPF_JMP_A(3));

        // If UDP
        EMIT(program, BPF_MOV64_IMM(BF_REG_4, sizeof(struct udphdr)));
        EMIT(program, BPF_JMP_A(1));

        // If ICMP
        EMIT(program, BPF_MOV64_IMM(BF_REG_4, sizeof(struct udphdr)));
    }

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // Copy the L3 header pointer to BF_REG_L3.
    EMIT(program, BPF_MOV64_REG(BF_REG_L4, BF_REG_RET));

    // If an error occurred, quit the program.
    {
        _cleanup_bf_jmpctx_ struct bf_jmpctx _ =
            bf_jmpctx_get(program, BPF_JMP_IMM(BPF_JNE, BF_REG_L4, 0, 0));
        EMIT(program,
             BPF_MOV64_IMM(BF_REG_RET, program->runtime.ops->get_verdict(
                                           BF_VERDICT_ACCEPT)));
        EMIT(program, BPF_EXIT_INSN());
    }

    return 0;
}
