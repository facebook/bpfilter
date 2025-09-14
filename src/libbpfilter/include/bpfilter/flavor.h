/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/verdict.h>

struct bf_program;

/**
 * @file flavor.h
 *
 * "Flavor" as defined by bpfilter are types of BPF program, characterized by
 * the prototype of the main function, the valid returns values, and the
 * way they are attached to the kernel.
 *
 * A flavor is used to defines specific part of the BPF program for a
 * codegen. For example: access to the packet's data, return value...
 */

/**
 * @enum bf_flavor
 *
 * Define a valid BPF flavor type for bpfilter.
 *
 * @var bf_flavor::BF_FLAVOR_TC
 *  TC flavor.
 * @var bf_flavor::BF_FLAVOR_NF
 *  For BPF_PROG_TYPE_NETFILTER programs. Expects a struct bpf_nf_ctx argument.
 */
enum bf_flavor
{
    BF_FLAVOR_TC,
    BF_FLAVOR_NF,
    BF_FLAVOR_XDP,

    /** cgroup BPF programs are a middle ground between TC and BPF_NETFILTER
     * programs:
     * - Input: <tt>struct __sk_buff</tt>
     * - Headers available: from L3
     * - Return code: 0 to drop, 1 to accept
     */
    BF_FLAVOR_CGROUP,
    _BF_FLAVOR_MAX,
};

/**
 * @struct bf_flavor_ops
 *
 * Define a set of operations that can be performed for a specific BPF flavor.
 *
 * @var bf_flavor_ops::gen_inline_epilogue
 *  Generate the epilogue of the BPF program.
 */
struct bf_flavor_ops
{
    /**
     * Generate the flavor-specific prologue of the BPF program.
     *
     * When this callback is called during the program generation, @c BPF_REG_1
     * contains the program's argument. It must then:
     * - Calculate and store the packet's size into the runtime context
     * - Store the input interface index into the runtime context
     * - If L2 is not available, set the L3 protocol ID into @c BPF_REG_7 and
     *   set @c l3_offset in the runtime context to 0.
     * - Call @ref bf_stub_parse_l2_ethhdr, @ref bf_stub_parse_l3_hdr, and
     *   @ref bf_stub_parse_l4_hdr depending on which headers are available.
     */
    int (*gen_inline_prologue)(struct bf_program *program);

    int (*gen_inline_epilogue)(struct bf_program *program);

    /**
     * Generates a flavor-specific return code corresponding to the verdict.
     *
     * Note this function only needs to handle terminal verdicts - verdicts that
     * stop further packet processing. Non-terminal verdicts do not need return
     * codes and therefore do not need to be handled by get_verdict().
     */
    int (*get_verdict)(enum bf_verdict verdict);
};

/**
 * Convert a bpfilter flavor to a string.
 *
 * @param flavor Flavor to convert. Must be valid.
 * @return String representation of @p flavor.
 */
const char *bf_flavor_to_str(enum bf_flavor flavor);
