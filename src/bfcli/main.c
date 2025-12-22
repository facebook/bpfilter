/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <stdarg.h>
#include <stdio.h>

#include <bpfilter/helper.h>
#include <bpfilter/logger.h>
#include <bpfilter/version.h>

#include "opts.h"

struct bfc_ruleset;

static void _bfc_print_version(FILE *stream, struct argp_state *state)
{
    UNUSED(state);

    (void)fprintf(stream, "bfcli version %s, libbpfilter version %s\n",
                  BF_VERSION, bf_version());
}

int main(int argc, char *argv[])
{
    _clean_bfc_opts_ struct bfc_opts opts = bfc_opts_default();
    int r;

    argp_program_version_hook = &_bfc_print_version;
    argp_program_bug_address = BF_CONTACT;

    bf_logger_setup();

    r = bfc_opts_parse(&opts, argc, argv);
    if (r < 0)
        return r;

    return opts.cmd->cb(&opts);
}

void yyerror(struct bfc_ruleset *ruleset, const char *fmt, ...)
{
    UNUSED(ruleset);

    va_list args;

    va_start(args, fmt);
    bf_err_v(fmt, args);
    va_end(args);
}
