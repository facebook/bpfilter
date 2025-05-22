
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/helper.h"

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "bfcli/lexer.h"
#include "bfcli/parser.h"
#include "core/logger.h"

int yy_read_buf_size;

int compute_buf_size(unsigned long chain_length)
{
    // Use heuristic formula to compute ideal buffer size given a chain length
    // buf_size = 2 ^ (round(log2(chain_length / 11)))

    chain_length >>= 4;

    int i = 0;
    for (; chain_length > 1; i++) {
        chain_length >>= 1;
    }

    return (2 << i);
}

int bfc_parse_file(const char *file, struct bfc_ruleset *ruleset)
{
    FILE *rules;
    int r;

    struct stat stt;
    stat(file, &stt);
    yy_read_buf_size = compute_buf_size(stt.st_size);

    rules = fopen(file, "r");
    if (!rules)
        return bf_err_r(errno, "failed to read rules from %s:", file);

    yyin = rules;

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    return r;
}

int bfc_parse_str(const char *str, struct bfc_ruleset *ruleset)
{
    YY_BUFFER_STATE buffer;
    int r;

    unsigned long str_size = strlen(str);
    yy_read_buf_size = compute_buf_size(str_size);

    buffer = yy_scan_string(str);

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    yy_delete_buffer(buffer);

    return r;
}
