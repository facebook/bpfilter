// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "fixup.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include "core/dump.h"
#include "shared/helper.h"

const char *bf_fixup_type_to_str(enum bf_fixup_type type)
{
    static const char *str[] = {
        [BF_CODEGEN_FIXUP_NEXT_RULE] = "BF_CODEGEN_FIXUP_NEXT_RULE",
        [BF_CODEGEN_FIXUP_END_OF_CHAIN] = "BF_CODEGEN_FIXUP_END_OF_CHAIN",
        [BF_CODEGEN_FIXUP_JUMP_TO_CHAIN] = "BF_CODEGEN_FIXUP_JUMP_TO_CHAIN",
        [BF_CODEGEN_FIXUP_COUNTERS_INDEX] = "BF_CODEGEN_FIXUP_COUNTERS_INDEX",
        [BF_CODEGEN_FIXUP_MAP_FD] = "BF_CODEGEN_FIXUP_MAP_FD",
        [BF_CODEGEN_FIXUP_FUNCTION_CALL] = "BF_CODEGEN_FIXUP_FUNCTION_CALL",
    };

    assert(type >= 0 && type < _BF_CODEGEN_FIXUP_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_CODEGEN_FIXUP_MAX);

    return str[type];
}

const char *bf_fixup_function_to_str(enum bf_fixup_function function)
{
    static const char *str[] = {
        [BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER] =
            "BF_CODEGEN_FIXUP_FUNCTION_ADD_COUNTER",
    };

    assert(function >= 0 && function < _BF_CODEGEN_FIXUP_FUNCTION_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_CODEGEN_FIXUP_FUNCTION_MAX);

    return str[function];
}

int bf_fixup_new(struct bf_fixup **fixup)
{
    assert(fixup);

    *fixup = calloc(1, sizeof(struct bf_fixup));
    if (!fixup)
        return -ENOMEM;

    return 0;
}

void bf_fixup_free(struct bf_fixup **fixup)
{
    assert(fixup);

    if (!*fixup)
        return;

    free(*fixup);
    *fixup = NULL;
}

void bf_fixup_dump(const struct bf_fixup *fixup,
                   char (*prefix)[DUMP_PREFIX_LEN])
{
    DUMP(prefix, "struct bf_fixup at %p", fixup);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "type: %s", bf_fixup_type_to_str(fixup->type));
    DUMP(prefix, "insn: %zu", fixup->insn);

    switch (fixup->type) {
    case BF_CODEGEN_FIXUP_NEXT_RULE:
    case BF_CODEGEN_FIXUP_END_OF_CHAIN:
    case BF_CODEGEN_FIXUP_JUMP_TO_CHAIN:
    case BF_CODEGEN_FIXUP_COUNTERS_INDEX:
    case BF_CODEGEN_FIXUP_MAP_FD:
        DUMP(prefix, "offset: %zu", fixup->offset);
        break;
    case BF_CODEGEN_FIXUP_FUNCTION_CALL:
        DUMP(prefix, "function: %s", bf_fixup_function_to_str(fixup->function));
        break;
    default:
        DUMP(prefix, "unknown bf_fixup_type: %d", fixup->type);
        break;
    };

    bf_dump_prefix_pop(prefix);
}
