/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>

#include "core/list.h"
#include "harness/test.h"
#include "harness/elf.h"
#include "harness/filter.h"
#include "harness/opts.h"
#include "harness/test.h"
#include "core/helper.h"

int main(int argc, char *argv[])
{
    _cleanup_bf_list_ bf_list *symbols = NULL;
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    _cleanup_bf_test_opts_ struct bf_test_opts *opts = NULL;
    int r;

    r = bf_test_opts_new(&opts, argc, argv);
    if (r) {
        fprintf(stderr, "failed to create a bf_test_opts object\n");
        return r;
    }

    r = bf_list_new(&symbols, (bf_list_ops[]) {
                                  {.free = (bf_list_ops_free)bf_elf_sym_free}});
    if (r)
        return r;

    r = bf_test_get_symbols(symbols);
    if (r)
        return r;

    r = bf_test_suite_new(&suite);
    if (r)
        return r;

    bf_list_foreach (symbols, sym_node) {
        struct bf_elf_sym *symbol = bf_list_node_get_data(sym_node);

        r = bf_test_suite_add_symbol(suite, symbol);
        if (r) {
            fprintf(stderr,
                    "WARNING: failed to add symbol '%s' to test suite: %s\n",
                    symbol->name, strerror(-r));
            continue;
        }
    }

    r = bf_test_suite_make_cmtests(suite);
    if (r)
        return r;

    int failed = 0;
    bf_list_foreach (&suite->groups, group_node) {
        bf_test_group *group = bf_list_node_get_data(group_node);

        if (!bf_test_filter_matches(opts->group_filter, group->name))
            continue;

        fprintf(stderr, "[STARTING TEST SUITE: %s]\n", group->name);

        r = _cmocka_run_group_tests(group->name, group->cmtests,
                                    bf_list_size(&group->tests), NULL, NULL);
        if (r)
            failed = 1;

        fprintf(stderr, "[FINISHED TEST SUITE: %s]\n\n", group->name);
    }

    if (failed)
        fail_msg("At least one test group failed!");

    return 0;
}
