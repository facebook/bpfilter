/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>

#include "core/list.h"
#include "harness/cmocka.h"
#include "harness/elf.h"
#include "harness/test.h"
#include "shared/helper.h"

int main(void)
{
    _cleanup_bf_list_ bf_list *symbols = NULL;
    _cleanup_bf_test_suite_ bf_test_suite *suite = NULL;
    int r;

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

        r = _cmocka_run_group_tests(group->name, group->cmtests,
                                    bf_list_size(&group->tests), NULL, NULL);
        if (r) {
            failed = 1;
            fprintf(stderr,
                    "WARNING: unit tests group '%s' faileds: "
                    "%s\n",
                    group->name, strerror(-r));
            continue;
        }
    }

    if (failed)
        fail_msg("At least one test group failed!");

    return 0;
}
