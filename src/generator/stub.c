/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "generator/stub.h"

#include <linux/bpf.h>

#include <arpa/inet.h>
#include <assert.h>

#include "external/filter.h"
#include "generator/program.h"

int bf_stub_memclear(struct bf_program *program, enum bf_reg addr_reg,
                     size_t size)
{
    assert(program);
    assert(!(size % 8));

    for (size_t i = 0; i < size; i += 8)
        EMIT(program, BPF_ST_MEM(BPF_DW, addr_reg, i, 0));

    return 0;
}

int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, enum bf_reg skb_reg)
{
    assert(program);

    // BF_ARG_1: address of the skb.
    if (BF_ARG_1 != skb_reg)
        EMIT(program, BPF_MOV64_IMM(BF_ARG_1, skb_reg));

    // BF_ARG_2: flags.
    EMIT(program, BPF_MOV64_IMM(BF_ARG_2, 0));

    // BF_ARG_1: address of the dynptr in the context.
    EMIT(program, BPF_MOV64_REG(BF_ARG_3, BF_REG_CTX));
    EMIT(program, BPF_ALU64_IMM(BPF_ADD, BF_ARG_3, BF_PROG_CTX_OFF(dynptr)));

    EMIT_KFUNC_CALL(program, "bpf_dynptr_from_skb");

    // If an error occurs, quit the program.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_IMM(BPF_JNE, BF_REG_RET, 0, 0));

    return 0;
}

int bf_stub_get_l2_eth_hdr(struct bf_program *program)
{
    assert(program);

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

    // If an error occurs, quit the program.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_IMM(BPF_JEQ, BF_REG_RET, 0, 0));

    // Copy the L2 header pointer to BF_REG_L2.
    EMIT(program, BPF_MOV64_REG(BF_REG_L2, BF_REG_RET));

    // Load L2 ethertype
    EMIT(program, BPF_LDX_MEM(BPF_H, BF_REG_1, BF_REG_L2,
                              offsetof(struct ethhdr, h_proto)));

    // Quit the program if L3 is not IPv4.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_IMM(BPF_JNE, BF_REG_1, ntohs(ETH_P_IP), 0));

    // Update L3 header offset.
    EMIT(program, BPF_ST_MEM(BPF_W, BF_REG_CTX, BF_PROG_CTX_OFF(l3_offset),
                             sizeof(struct ethhdr)));

    return 0;
}

int bf_stub_get_l3_ipv4_hdr(struct bf_program *program)
{
    assert(program);

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

    // If an error occurs, quit the program.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_IMM(BPF_JEQ, BF_REG_RET, 0, 0));

    // Copy the L3 header pointer to BF_REG_L3.
    EMIT(program, BPF_MOV64_REG(BF_REG_L3, BF_REG_RET));

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
         BPF_STX_MEM(BPF_W, BF_REG_CTX, BF_REG_1, BF_PROG_CTX_OFF(l4_proto)));

    return 0;
}

int bf_stub_get_l4_hdr(struct bf_program *program)
{
    assert(program);

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
         BPF_LDX_MEM(BPF_W, BF_REG_4, BF_REG_CTX, BF_PROG_CTX_OFF(l4_proto)));

    {
        // If L4 protocol is TCP.
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, IPPROTO_TCP, 3));

        // If L4 protocol is UDP.
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, IPPROTO_UDP, 4));

        // If L4 protocol is ICMP.
        EMIT(program, BPF_JMP_IMM(BPF_JEQ, BF_REG_4, IPPROTO_ICMP, 5));

        // Protocol is not supported, skip slice request.
        EMIT(program, BPF_JMP_A(8));

        // If TCP
        EMIT(program, BPF_MOV64_IMM(BF_ARG_4, sizeof(struct tcphdr)));
        EMIT(program, BPF_JMP_A(3));

        // If UDP
        EMIT(program, BPF_MOV64_IMM(BF_ARG_4, sizeof(struct udphdr)));
        EMIT(program, BPF_JMP_A(1));

        // If ICMP
        EMIT(program, BPF_MOV64_IMM(BF_ARG_4, sizeof(struct udphdr)));
    }

    EMIT_KFUNC_CALL(program, "bpf_dynptr_slice");

    // If an error occurs, quit the program.
    EMIT_FIXUP(program, BF_CODEGEN_FIXUP_END_OF_CHAIN,
               BPF_JMP_IMM(BPF_JEQ, BF_REG_RET, 0, 0));

    // Copy the L3 header pointer to BF_REG_L3.
    EMIT(program, BPF_MOV64_REG(BF_REG_L4, BF_REG_RET));

    return 0;
}
