/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/dump.h"

enum bf_fixup_insn_type
{
    BF_CODEGEN_FIXUP_INSN_OFF,
    BF_CODEGEN_FIXUP_INSN_IMM,
    _BF_CODEGEN_FIXUP_INSN_MAX_MAX,
};

enum bf_fixup_function
{
    BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER,
    _BF_CODEGEN_FIXUP_FUNCTION_MAX,
};

enum bf_fixup_type
{
    BF_CODEGEN_FIXUP_NEXT_RULE,
    BF_CODEGEN_FIXUP_END_OF_CHAIN,
    BF_CODEGEN_FIXUP_JUMP_TO_CHAIN,
    BF_CODEGEN_FIXUP_COUNTERS_INDEX,
    BF_CODEGEN_FIXUP_MAP_FD,
    BF_CODEGEN_FIXUP_FUNCTION_CALL,
    _BF_CODEGEN_FIXUP_MAX
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
        enum bf_fixup_function function;
    };
};

#define _cleanup_bf_fixup_ __attribute__((cleanup(bf_fixup_free)))

const char *bf_fixup_type_to_str(enum bf_fixup_type type);
const char *bf_fixup_function_to_str(enum bf_fixup_function function);

int bf_fixup_new(struct bf_fixup **fixup);
void bf_fixup_free(struct bf_fixup **fixup);
void bf_fixup_dump(const struct bf_fixup *fixup,
                   char (*prefix)[DUMP_PREFIX_LEN]);
