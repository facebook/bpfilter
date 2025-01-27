/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_program;

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
int bf_stub_make_ctx_xdp_dynptr(struct bf_program *program, int md_reg);

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
int bf_stub_make_ctx_skb_dynptr(struct bf_program *program, int skb_reg);

/**
 * Emit instructions to get a dynptr slice for the packet's L2 Ethernet
 * header.
 *
 * The Ethernet header is processed the following way:
 * - Create a BPF dynamic pointer slice for the header.
 * - If the slice creation fails, the error counter is updated and the
 *   program accepts the packet
 * - The header address returned by @c bpf_dynptr_slice is stored in
 *   @c bf_program_context.l2_hdr
 * - The L3 protocol ID (extracted from the ethertype field) is stored in @c r7
 * - The offset of the L3 header is stored in  @c bf_program_context.l2_offset
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l2_ethhdr(struct bf_program *program);

/**
 * Emit instructions to get a dynptr slice for the packet's L3 IPv4
 * header.
 *
 * This function behaves similarly to @ref bf_stub_parse_l2_ethhdr but for the
 * L3 header, with the following differences:
 * - The size of the slice to request depends on the L3 protocol ID stored in @c r7
 * - Once the slice has been requested, the L3 header is processed to extract
 *   the offset of the L4 header and the L4 protocol ID
 *
 * If the L3 protocol is not supported, this function returns before requesting
 * a dynamic pointer slice, and the L3 protocol ID register is set to 0.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l3_hdr(struct bf_program *program);

/**
 * Emit instructions to get a dynptr slice for the packet's L4 header.
 *
 * This function behaves similarly to @ref bf_stub_parse_l2_ethhdr but for the
 * L4 header, with the following differences:
 * - The size of the slice to request depends on the L4 protocol ID stored in @c r8
 * - There is no logic to process the L4 header and determine the L5 protocol
 *
 * If the L4 protocol is not supported, this function returns before requesting
 * a dynamic pointer slice, and the L4 protocol ID register is set to 0.
 *
 * @param program Program to emit instructions into.
 * @return 0 on success, or negative errno value on error.
 */
int bf_stub_parse_l4_hdr(struct bf_program *program);
