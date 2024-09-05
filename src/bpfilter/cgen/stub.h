/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "bpfilter/cgen/reg.h"

struct bf_program;

/**
 * Emit instructions to clear a memory region.
 *
 * Generate BPF instructions to clear (set to 0) a memory region, from a
 * register containing the address of the memory region to clear, and the size.
 *
 * @warning The memory area *must* be aligned on 8 bytes (address and size), as
 * the region is cleared 8 bytes at a time.
 *
 * @param program Program to emit instructions into.
 * @param addr_reg Register containing the address to clear.
 * @param size Size of the memory region to clear.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_memclear(struct bf_program *program, enum bf_reg addr_reg,
                     size_t size);
/**
 * Emit instructions to get a dynptr for an XDP program.
 *
 * Prepare arguments and call bpf_dynptr_from_xdp(). If the return value is
 * different from 0, jump to the end of the program and accept the packet.
 *
 * The initialised dynptr is stored in the program's runtime context.
 *
 * @param program Program to emit instructions into.
 * @param md_reg Scratch register containing the pointer to the xdp_md.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, enum bf_reg md_reg);

/**
 * Emit instructions to get a dynptr for an XDP program.
 *
 * Prepare arguments and call bpf_dynptr_from_skb(). If the return value is
 * different from 0, jump to the end of the program and accept the packet.
 *
 * The initialised dynptr is stored in the program's runtime context.
 *
 * @param program Program to emit instructions into.
 * @param skb_reg Scratch register containing the pointer to the skb.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_make_ctx_skb_dynptr(struct bf_program *program,
                                enum bf_reg skb_reg);

/**
 * Emit instructions to get a dynptr slice for the packet's L2 Ethernet
 * header.
 *
 * Store bpf_dynptr_slice arguments into:
 * - BF_ARG_1: pointer to the dynptr located in the context.
 * - BF_ARG_2: offset of the slice, in the dynptr. Always 0, as L2 Ethernet is
 *   the first header.
 * - BF_ARG_3: pointer to the buffer to store the slice into. Each header buffer
 *   is located in the context.
 * - BF_ARG_4: size of the buffer. Always ETH_HLEN, as L2 Ethernet is the first
 *   header.
 * Then, call bpf_dynptr_slice(). If the return value is different from 0, jump
 * to the end of the program.
 * Finally:
 * - Copy the address of the header into BF_REG_L2.
 * - Load the header's h_proto field to determine the L3 protocol. If L3
 *   protocol is not IPv4 (the only supported protocol for now), jump to the
 *   end of the program.
 * - Store the offset of the L3 header in the context.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l2_ethhdr(struct bf_program *program);

/**
 * Emit instructions to get a dynptr slice for the packet's L3 IPv4
 * header.
 *
 * Store bpf_dynptr_slice arguments into:
 * - BF_ARG_1: pointer to the dynptr located in the context.
 * - BF_ARG_2: offset of the slice, in the dynptr. Get it from l3_offset field
 *   in the context. This field is either 0, or set when processing layer 2
 *   header.
 * - BF_ARG_3: pointer to the buffer to store the slice into.
 * - BF_ARG_4: size of the buffer, expected to be an IPv4 header.
 * Then, call bpf_dynptr_slice(). If the return value is different from 0, jump
 * to the end of the program.
 * Finally:
 * - Store the address of the header into BF_REG_L3.
 * - Compute the offset of the L4 header:
 *   - Load ip.ihl into BF_REG_1
 *   - Add ctx.l3_offset to it.
 *   - Copy it back to the context.
 * - Store L4 protocol into the context.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l3_hdr(struct bf_program *program);

/**
 * Emit instructions to get a dynptr slice for the packet's L4 header.
 *
 * Store bpf_dynptr_slice arguments into:
 * - BF_ARG_1: pointer to the dynptr located in the context.
 * - BF_ARG_2: offset of the slice, in the dynptr. Get it from l4_offset field
 *   in the context. This field is set when processing layer 2 header.
 * - BF_ARG_3: pointer to the buffer to store the slice into.
 * - BF_ARG_4: size of the buffer, need to be computed depending ctx.l4_proto.
 *   If ctx.l4_proto is not supported, jump to the end of the program.
 * Then, call bpf_dynptr_slice(). If the return value is different from 0, jump
 * to the end of the program.
 * Finally, copy the address of the header into BF_REG_L4.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l4_hdr(struct bf_program *program);
