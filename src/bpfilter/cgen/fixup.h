/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "bpfilter/cgen/elfstub.h"
#include "core/dump.h"

/**
 * Field to fixup in a @c bpf_insn structure.
 */
enum bf_fixup_insn
{
    BF_FIXUP_INSN_OFF,
    BF_FIXUP_INSN_IMM,
    _BF_FIXUP_INSN_MAX,
};

/**
 * Custom function to call.
 *
 * A fixup can be used to jump to a custom function defined later in the
 * BPF program. This enum contains the list of functions available.
 */
enum bf_fixup_func
{
    BF_FIXUP_FUNC_UPDATE_COUNTERS,
    _BF_FIXUP_FUNC_MAX,
};

/**
 * Type of the fixup.
 *
 * Defines how a fixup should be processed.
 */
enum bf_fixup_type
{
    /// Jump to the beginning of the next rule.
    BF_FIXUP_TYPE_JMP_NEXT_RULE,
    /// Set the counters map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_COUNTERS_MAP_FD,
    /// Set the printer map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_PRINTER_MAP_FD,
    /// Set a set map file descriptor in the @c BPF_LD_MAP_FD instruction.
    BF_FIXUP_TYPE_SET_MAP_FD,
    /// Jump to a custom function.
    BF_FIXUP_TYPE_FUNC_CALL,
    /// Call an ELF stub.
    BF_FIXUP_ELFSTUB_CALL,
    _BF_FIXUP_TYPE_MAX
};

union bf_fixup_attr
{
    size_t set_index;
    enum bf_fixup_func function;
    enum bf_elfstub_id elfstub_id;
};

struct bf_fixup
{
    enum bf_fixup_type type;
    size_t insn;
    union bf_fixup_attr attr;
};

#define _free_bf_fixup_ __attribute__((cleanup(bf_fixup_free)))

int bf_fixup_new(struct bf_fixup **fixup, enum bf_fixup_type type,
                 size_t insn_offset, const union bf_fixup_attr *attr);
void bf_fixup_free(struct bf_fixup **fixup);
void bf_fixup_dump(const struct bf_fixup *fixup, prefix_t *prefix);
