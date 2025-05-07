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


#define streq(str, expected) (str) && bf_streq(str, expected)

#define BFC_COMMAND_NAME_LEN 32
static char _bfc_command_name[BFC_COMMAND_NAME_LEN];

int main(int argc, char *argv[])
{
    const char *name = argv[0];
    const char *obj_str = NULL;
    const char *action_str = NULL;
    int argv_skip = 0;
    int r;

    if (argc > 1 && argv[1][0] != '-') {
        obj_str = argv[1];
        ++argv_skip;
    }

    if (obj_str && argc > 2 && argv[2][0] != '-') {
        action_str = argv[2];
        ++argv_skip;
    }

    argv += argv_skip;
    argc -= argv_skip;

    bf_logger_setup();

    // If any of the arguments is --version, print the version and return.
    for (int i = 0; i < argc; ++i) {
        if (bf_streq("--version", argv[i])) {
            bf_info("bfcli version %s, libbpfilter version %s", BF_VERSION,
                    bf_version());
            exit(0);
        }
    }

    (void)snprintf(_bfc_command_name, BFC_COMMAND_NAME_LEN, "%s %s %s", name,
                   obj_str, action_str);
    argv[0] = _bfc_command_name;

    if (streq(obj_str, "ruleset") && streq(action_str, "set")) {
        r = bfc_ruleset_set(argc, argv);
    } else if (streq(obj_str, "ruleset") && streq(action_str, "get")) {
        r = bfc_ruleset_get(argc, argv);
    } else if (streq(obj_str, "ruleset") && streq(action_str, "flush")) {
        r = bf_cli_ruleset_flush();
    } else if (streq(obj_str, "chain") && streq(action_str, "set")) {
        r = bfc_chain_set(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "get")) {
        r = bfc_chain_get(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "load")) {
        r = bfc_chain_load(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "attach")) {
        r = bfc_chain_attach(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "update")) {
        r = bfc_chain_update(argc, argv);
    } else if (streq(obj_str, "chain") && streq(action_str, "flush")) {
        r = bfc_chain_flush(argc, argv);
    } else {
        return bf_err_r(-EINVAL, "unrecognized object '%s' and action '%s'",
                        obj_str, action_str);
    }

    return r;
}

void yyerror(struct bfc_ruleset *ruleset, const char *fmt, ...)
{
    UNUSED(ruleset);

    va_list args;

    va_start(args, fmt);
    bf_err_v(fmt, args);
    va_end(args);
}
