/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "dump.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define BF_DUMP_HEXDUMP_LEN 8
#define BF_DUMP_TOKEN_LEN 5

void bf_dump_prefix_push(prefix_t *prefix)
{
    char *_prefix = *prefix;
    size_t len = strlen(_prefix);

    if (len) {
        /* If the prefix string is not empty, then we need to either
         * continue the previous branch (with a pipe), or remove
         * it altogether if it stopped. */
        strncpy(&_prefix[len - 4], _prefix[len - 4] == '`' ? "    " : "|   ",
                BF_DUMP_TOKEN_LEN);
    }

    if (len + BF_DUMP_TOKEN_LEN > DUMP_PREFIX_LEN)
        return;

    strncpy(&_prefix[len], "|-- ", BF_DUMP_TOKEN_LEN);
}

prefix_t *bf_dump_prefix_last(prefix_t *prefix)
{
    char *_prefix = *prefix;
    size_t len = strlen(_prefix);

    if (len)
        strncpy(&_prefix[len - 4], "`-- ", BF_DUMP_TOKEN_LEN);

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
        strncpy(&_prefix[len - 8], "|-- ", BF_DUMP_TOKEN_LEN);
}

void bf_dump_hex(prefix_t *prefix, const void *data, size_t len)
{
    // 5 characters per byte (0x%02x) + 1 for the null terminator.
    char buf[(BF_DUMP_HEXDUMP_LEN * BF_DUMP_TOKEN_LEN) + 1];
    const void *end = data + len;

    while (data < end) {
        char *line = buf;
        for (size_t i = 0; i < BF_DUMP_HEXDUMP_LEN && data < end; ++i, ++data)
            line += sprintf(line, "0x%02x ", *(unsigned char *)data);

        DUMP((data == end ? bf_dump_prefix_last(prefix) : prefix), "%s", buf);
    }
}
