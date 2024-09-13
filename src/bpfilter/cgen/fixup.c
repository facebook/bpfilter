// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "fixup.h"

#include <errno.h>
#include <stdlib.h>

#include "core/dump.h"
#include "core/helper.h"

const char *bf_fixup_type_to_str(enum bf_fixup_type type)
{
    static const char *str[] = {
        [BF_FIXUP_TYPE_JMP_NEXT_RULE] = "BF_FIXUP_TYPE_JMP_NEXT_RULE",
        [BF_FIXUP_TYPE_COUNTERS_MAP_FD] = "BF_FIXUP_TYPE_COUNTERS_MAP_FD",
        [BF_FIXUP_TYPE_PRINTER_MAP_FD] = "BF_FIXUP_TYPE_PRINTER_MAP_FD",
        [BF_FIXUP_TYPE_FUNC_CALL] = "BF_FIXUP_TYPE_FUNC_CALL",
    };

    bf_assert(type >= 0 && type < _BF_FIXUP_TYPE_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_FIXUP_TYPE_MAX);

    return str[type];
}

const char *bf_fixup_function_to_str(enum bf_fixup_func function)
{
    static const char *str[] = {
        [BF_FIXUP_FUNC_ADD_COUNTER] = "BF_FIXUP_FUNC_ADD_COUNTER",
    };

    bf_assert(function >= 0 && function < _BF_FIXUP_FUNC_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_FIXUP_FUNC_MAX);

    return str[function];
}

int bf_fixup_new(struct bf_fixup **fixup)
{
    bf_assert(fixup);

    *fixup = calloc(1, sizeof(struct bf_fixup));
    if (!fixup)
        return -ENOMEM;

    return 0;
}

void bf_fixup_free(struct bf_fixup **fixup)
{
    bf_assert(fixup);

    if (!*fixup)
        return;

    free(*fixup);
    *fixup = NULL;
}

void bf_fixup_dump(const struct bf_fixup *fixup, prefix_t *prefix)
{
    bf_assert(fixup);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_fixup at %p", fixup);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "type: %s", bf_fixup_type_to_str(fixup->type));
    DUMP(prefix, "insn: %zu", fixup->insn);

    switch (fixup->type) {
    case BF_FIXUP_TYPE_JMP_NEXT_RULE:
        DUMP(prefix, "offset: %zu", fixup->offset);
        break;
    case BF_FIXUP_TYPE_COUNTERS_MAP_FD:
    case BF_FIXUP_TYPE_PRINTER_MAP_FD:
        DUMP(prefix, "immediate: %zu", fixup->offset);
        break;
    case BF_FIXUP_TYPE_FUNC_CALL:
        DUMP(prefix, "function: %s", bf_fixup_function_to_str(fixup->function));
        break;
    default:
        DUMP(prefix, "unknown bf_fixup_type: %d", fixup->type);
        break;
    };

    bf_dump_prefix_pop(prefix);
}
