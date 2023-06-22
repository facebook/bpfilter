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
 */
enum bf_flavor
{
    BF_FLAVOR_TC,
    _BF_FLAVOR_MAX,
};

/**
 * @struct bf_flavor_ops
 *
 * Define a set of operations that can be performed for a specific BPF flavor.
 *
 * @var bf_flavor_ops::gen_inline_prologue
 *  Generate the prologue of the BPF program.
 * @var bf_flavor_ops::load_packet_data
 *  Load the packet data pointer into a register.
 * @var bf_flavor_ops::load_packet_data_end
 *  Load the packet data end pointer into a register.
 * @var bf_flavor_ops::gen_inline_epilogue
 *  Generate the epilogue of the BPF program.
 */
struct bf_flavor_ops
{
    int (*gen_inline_prologue)(struct bf_program *program);
    int (*load_packet_data)(struct bf_program *program, int reg);
    int (*load_packet_data_end)(struct bf_program *program, int reg);
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
