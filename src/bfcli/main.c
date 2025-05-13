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

#include "bfcli/chain.h"
#include "bfcli/helper.h"
#include "bfcli/opts.h"
#include "bfcli/print.h"
#include "bfcli/ruleset.h"
#include "core/chain.h"
#include "core/helper.h"
#include "core/hook.h"
#include "core/list.h"
#include "core/logger.h"
#include "core/request.h"
#include "core/response.h"
#include "core/set.h"
#include "libbpfilter/bpfilter.h"
#include "version.h"

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
