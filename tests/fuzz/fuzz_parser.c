/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <bpfilter/list.h>

#include "helper.h"
#include "ruleset.h"

// Stub for parser error handling - suppress output during fuzzing
void yyerror(struct bfc_ruleset *ruleset, const char *fmt, ...)
{
    (void)ruleset;
    (void)fmt;
}

// Stub for ruleset dumping - not used during parsing
int bfc_ruleset_dump(bf_list *chains, bf_list *hookopts, bf_list *counters)
{
    (void)chains;
    (void)hookopts;
    (void)counters;

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    _clean_bfc_ruleset_ struct bfc_ruleset ruleset = bfc_ruleset_default();
    _cleanup_free_ char *str = NULL;

    str = malloc(size + 1);
    if (!str)
        return 0;

    memcpy(str, data, size);
    str[size] = '\0';

    // Replace '#' with space to prevent comments from hiding input
    for (size_t i = 0; i < size; i++) {
        if (str[i] == '#')
            str[i] = ' ';
    }

    if (bfc_parse_str(str, &ruleset))
        return -1;

    return 0;
}
