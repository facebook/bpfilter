/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

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
    BF_FIXUP_FUNC_ADD_COUNTER,
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
    /// Jump to a custom function.
    BF_FIXUP_TYPE_FUNC_CALL,
    _BF_FIXUP_TYPE_MAX
};

/**
 * @union bf_fixup_attr
 *
 * Attributes to use when processing the fixups.
 */
union bf_fixup_attr
{
    struct
    {
        int map_fd;
    };
};

struct bf_fixup
{
    enum bf_fixup_type type;
    size_t insn;

    union
    {
        size_t offset;
        enum bf_fixup_func function;
    };
};

#define _cleanup_bf_fixup_ __attribute__((cleanup(bf_fixup_free)))

const char *bf_fixup_type_to_str(enum bf_fixup_type type);
const char *bf_fixup_function_to_str(enum bf_fixup_func function);

int bf_fixup_new(struct bf_fixup **fixup);
void bf_fixup_free(struct bf_fixup **fixup);
void bf_fixup_dump(const struct bf_fixup *fixup, prefix_t *prefix);
