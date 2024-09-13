// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "fixup.h"

#include <errno.h>
#include <stdlib.h>

#include "core/dump.h"
#include "core/helper.h"

int bf_fixup_new(struct bf_fixup **fixup, enum bf_fixup_type type,
                 size_t insn_offset, const union bf_fixup_attr *attr)
{
    bf_assert(fixup);

    *fixup = calloc(1, sizeof(struct bf_fixup));
    if (!fixup)
        return -ENOMEM;

    (*fixup)->type = type;
    (*fixup)->insn = insn_offset;

    if (attr)
        (*fixup)->attr = *attr;

    return 0;
}

void bf_fixup_free(struct bf_fixup **fixup)
{
    bf_assert(fixup);

    if (!*fixup)
        return;

    freep((void *)fixup);
}

static const char *_bf_fixup_type_to_str(enum bf_fixup_type type)
{
    static const char *str[] = {
        [BF_FIXUP_TYPE_JMP_NEXT_RULE] = "BF_FIXUP_TYPE_JMP_NEXT_RULE",
        [BF_FIXUP_TYPE_COUNTERS_MAP_FD] = "BF_FIXUP_TYPE_COUNTERS_MAP_FD",
        [BF_FIXUP_TYPE_PRINTER_MAP_FD] = "BF_FIXUP_TYPE_PRINTER_MAP_FD",
        [BF_FIXUP_TYPE_FUNC_CALL] = "BF_FIXUP_TYPE_FUNC_CALL",
    };

    bf_assert(0 <= type && type < _BF_FIXUP_TYPE_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_FIXUP_TYPE_MAX);

    return str[type];
}

static const char *_bf_fixup_func_to_str(enum bf_fixup_func func)
{
    static const char *str[] = {
        [BF_FIXUP_FUNC_ADD_COUNTER] = "BF_FIXUP_FUNC_ADD_COUNTER",
    };

    bf_assert(0 <= func && func < _BF_FIXUP_FUNC_MAX);
    static_assert(ARRAY_SIZE(str) == _BF_FIXUP_FUNC_MAX);

    return str[func];
}

void bf_fixup_dump(const struct bf_fixup *fixup, prefix_t *prefix)
{
    bf_assert(fixup);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_fixup at %p", fixup);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "type: %s", _bf_fixup_type_to_str(fixup->type));
    DUMP(prefix, "insn: %zu", fixup->insn);

    switch (fixup->type) {
    case BF_FIXUP_TYPE_JMP_NEXT_RULE:
        DUMP(prefix, "offset: %zu", fixup->offset);
        break;
    case BF_FIXUP_TYPE_COUNTERS_MAP_FD:
    case BF_FIXUP_TYPE_PRINTER_MAP_FD:
        // No specific value to dump
        break;
    case BF_FIXUP_TYPE_FUNC_CALL:
        DUMP(prefix, "function: %s",
             _bf_fixup_func_to_str(fixup->attr.function));
        break;
    default:
        DUMP(prefix, "unsupported bf_fixup_type: %d", fixup->type);
        break;
    };

    bf_dump_prefix_pop(prefix);
}
