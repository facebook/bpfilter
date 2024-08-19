/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/verdict.h"

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
    _BF_FLAVOR_MAX,
};

/**
 * @brief Extra attribute to share between call during 2-steps attach.
 */
union bf_flavor_attach_attr
{
    /** File descriptor of the link created before the existing program has
     * been detached. */
    int pre_unload_link_fd;
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
    int (*get_verdict)(enum bf_verdict verdict);

    /**
     * @brief Attach a loaded BPF program to the kernel, before unloading the
     * out-of-date program.
     *
     * There are two callbacks used to attach a program for a given flavor,
     * which are used to ensure the new program is attached before the existing
     * program (attached to the same hook) is detached. @ref
     * attach_prog_pre_unload is called before the existing program is detached
     * and unloaded, @ref attach_prog_post_unload is called once the existing
     * program has been detached from the kernel and unloaded.
     *
     * This 2-steps process is mandatory for specific flavor (e.g. netfilter),
     * as we want to avoid downtime, while ensuring a given program (for a
     * specific hook and interface) will always use the same priority.
     *
     * @param program Program to attach.
     * @param prog_fd File descriptor of the loaded program.
     * @param attr Extra attribute to share between call during 2-steps attach.
     * @return 0 on success, negative ernno code on failure.
     */
    int (*attach_prog_pre_unload)(struct bf_program *program, int *prog_fd,
                                  union bf_flavor_attach_attr *attr);

    /**
     * @brief Attach a loaded BPF program to the kernel, after the out-of-date
     * program has been detached.
     *
     * See @ref attach_prog_pre_unload for details.
     *
     * @param program Program to attach.
     * @param prog_fd File descriptor of the loaded program.
     * @param attr Extra attribute to share between call during 2-steps attach.
     * @return 0 on success, negative ernno code on failure.
     */
    int (*attach_prog_post_unload)(struct bf_program *program, int *prog_fd,
                                   union bf_flavor_attach_attr *attr);

    /**
     * Load and attach a BPF program.
     *
     * @p new_prog is the new program to be attached to the hook, and @p
     * old_prog is the existing one.
     * @p old_prog can be NULL, if no program is already attached. The exact
     * load and attach mechanism is up to the flavor: direct attach, BPF link,
     * ...
     *
     * If @p old_prog is not NULL, the replacement of @p old_prog by @p new_prog
     * must be atomic.
     *
     * @param new_prog New BPF program to attach to the kernel. Can't be NULL.
     * @param old_prog Previous program to replace.
     * @return 0 on success, or negative errno value on failure.
     */
    int (*attach_prog)(struct bf_program *new_prog,
                       struct bf_program *old_prog);

    int (*detach_prog)(struct bf_program *program);
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
