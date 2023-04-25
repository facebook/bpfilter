/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "dump.h"

#include <stddef.h>
#include <string.h>

void bf_dump_prefix_push(char *prefix)
{
        size_t len = strlen(prefix);

        if (len) {
                /* If the prefix string is not empty, then we need to either
				 * continue the previous branch (with a pipe), or remove
                 * it altogether if it stopped. */
                strncpy(&prefix[len - 4],
                        prefix[len - 4] == '`' ? "    " : "|   ", 5);
        }

        if (len + 5 > DUMP_PREFIX_LEN)
                return;


        strncpy(&prefix[len], "|-- ", 5);
}

char *bf_dump_prefix_last(char *prefix)
{
        size_t len = strlen(prefix);

        if (len)
                strncpy(&prefix[len - 4], "`-- ", 5);

        return prefix;
}

void bf_dump_prefix_pop(char *prefix)
{
        size_t len = strlen(prefix);

        if (!len)
                return;

        prefix[len - 4] = '\0';

        // Ensure we have a branch to the next item.
        if (len - 4)
                strncpy(&prefix[len - 8], "|-- ", 5);
}
