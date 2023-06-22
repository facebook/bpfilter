/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "dump.h"

#include <stddef.h>
#include <string.h>

void bf_dump_prefix_push(prefix_t *prefix)
{
    char *_prefix = *prefix;
    size_t len = strlen(_prefix);

    if (len) {
        /* If the prefix string is not empty, then we need to either
         * continue the previous branch (with a pipe), or remove
         * it altogether if it stopped. */
        strncpy(&_prefix[len - 4], _prefix[len - 4] == '`' ? "    " : "|   ",
                5);
    }

    if (len + 5 > DUMP_PREFIX_LEN)
        return;

    strncpy(&_prefix[len], "|-- ", 5);
}

prefix_t *bf_dump_prefix_last(prefix_t *prefix)
{
    char *_prefix = *prefix;
    size_t len = strlen(_prefix);

    if (len)
        strncpy(&_prefix[len - 4], "`-- ", 5);

    return prefix;
}

void bf_dump_prefix_pop(prefix_t *prefix)
{
    char *_prefix = *prefix;
    size_t len = strlen(_prefix);

    if (!len)
        return;

    _prefix[len - 4] = '\0';

    // Ensure we have a branch to the next item.
    if (len - 4)
        strncpy(&_prefix[len - 8], "|-- ", 5);
}
