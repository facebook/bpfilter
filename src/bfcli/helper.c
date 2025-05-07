
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bfcli/helper.h"

#include <errno.h>
#include <stdio.h>

#include "bfcli/lexer.h"
#include "bfcli/parser.h"
#include "core/logger.h"

int bfc_parse_file(const char *file, struct bfc_ruleset *ruleset)
{
    FILE *rules;
    int r;

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

    buffer = yy_scan_string(str);

    r = yyparse(ruleset);
    if (r == 1)
        r = bf_err_r(-EINVAL, "failed to parse rules, invalid syntax");
    else if (r == 2)
        r = bf_err_r(-ENOMEM, "failed to parse rules, not enough memory");

    yy_delete_buffer(buffer);

    return r;
}
