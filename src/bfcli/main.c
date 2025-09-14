/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfilter/bpfilter.h>
#include <bpfilter/chain.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/request.h>
#include <bpfilter/response.h>
#include <bpfilter/set.h>
#include <bpfilter/version.h>

#include "chain.h"
#include "helper.h"
#include "opts.h"
#include "print.h"
#include "ruleset.h"

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
