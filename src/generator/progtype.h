/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/context.h"

struct bf_codegen;

/**
 * @enum bf_progtype
 *
 * Define a valid BPF program type for bpfilter. Depending the program type,
 * bpfilter will generate different BPF bytecode. For example, the TC program
 * type will generate a BPF program that can be attached to a TC classifier.
 *
 * @var bf_progtype::BF_PROGTYPE_TC
 *  TC program type.
 */
enum bf_progtype
{
    BF_PROGTYPE_TC,
    __BF_PROGTYPE_MAX,
};

/**
 * @struct bf_progtype_ops
 *
 * Define a set of operations that can be performed on a BPF program type.
 *
 * @var bf_progtype_ops::gen_inline_prologue
 *  Generate the prologue of the BPF program.
 * @var bf_progtype_ops::load_packet_data
 *  Load the packet data pointer into a register.
 * @var bf_progtype_ops::load_packet_data_end
 *  Load the packet data end pointer into a register.
 * @var bf_progtype_ops::gen_inline_epilogue
 *  Generate the epilogue of the BPF program.
 */
struct bf_progtype_ops
{
    void (*gen_inline_prologue)(struct bf_codegen *codegen);
    void (*load_packet_data)(struct bf_codegen *codegen, int reg);
    void (*load_packet_data_end)(struct bf_codegen *codegen, int reg);
    void (*gen_inline_epilogue)(struct bf_codegen *codegen);
};

/**
 * @brief Get the operations for a given BPF program type.
 *
 * @param type BPF program type. Must be valid.
 * @return Ops structure for a given BPF program type.
 */
const struct bf_progtype_ops *bf_progtype_ops_get(enum bf_progtype type);

/**
 * @brief Convert a bpfilter program type to a string.
 *
 * @param type Program type to convert. If invalid, NULL is returned.
 * @return String representation of @p type, or NULL if @p type is invalid.
 */
const char *bf_progtype_to_str(enum bf_progtype type);

/**
 * @brief Get the expected program type for a given hook.
 *
 * @param hook BPF hook. If invalid, __BF_PROGTYPE_MAX is returned.
 * @return bpfilter program type corresponding to @p hook, or __BF_PROGTYPE_MAX
 *  if @p hook is invalid.
 */
enum bf_progtype bf_hook_to_progtype(enum bf_hooks hook);
