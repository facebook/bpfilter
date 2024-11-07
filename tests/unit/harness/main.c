/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <stdio.h>

#include "core/list.h"
#include "harness/test.h"
#include "harness/sym.h"
#include "harness/opts.h"
#include "harness/test.h"
#include "core/helper.h"

int main(int argc, char *argv[])
{
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    _cleanup_bf_test_opts_ struct bf_test_opts *opts = NULL;
    int failed = 0;
    int r;

    r = bf_test_opts_new(&opts, argc, argv);
    if (r) {
        fprintf(stderr, "failed to create a bf_test_opts object\n");
        return r;
    }

    r = bf_test_discover_test_suite(&suite);
    if (r < 0)
        return bf_err_r(r, "test suite discovery failed");

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
