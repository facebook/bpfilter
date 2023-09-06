/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/target.h"

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
     * @brief Generate the flavor-specific prologue of the BPF program.
     *
     * This function can assume BF_ARG_1 contains the first argument passed
     * to the program, and BF_REG_CTX is properly set, pointing to an
     * initialised context.
     *
     * The purpose of this callback is to:
     * - Ensure ctx.dynptr is a valid BPF dynptr to the packet data.
     * - ctx.pkt_size contains the packet size.
     * - BPF dynptr slices to layer 2, 3, and 4 (if relevant) are stored within
     *   the context, and BF_REG_L{2, 3, 4} are updated to contain the address
     *   of the relevant header.
     */
    int (*gen_inline_prologue)(struct bf_program *program);
    int (*gen_inline_epilogue)(struct bf_program *program);
    int (*convert_return_code)(enum bf_target_standard_verdict verdict);
    int (*load_img)(struct bf_program *program, int fd);
    int (*unload_img)(struct bf_program *program);
};

/**
 * @brief Get the operations structure for a given BPF flavor.
 *
 * @param type BPF flavor. Must be valid.
 * @return Ops structure for a given BPF flavor.
 */
const struct bf_flavor_ops *bf_flavor_ops_get(enum bf_flavor flavor);

/**
 * @brief Convert a bpfilter flavor to a string.
 *
 * @param flavor Flavor to convert. Must be valid.
 * @return String representation of @p flavor.
 */
const char *bf_flavor_to_str(enum bf_flavor flavor);
