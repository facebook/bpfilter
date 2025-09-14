/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <argp.h>
#include <stdio.h>

#include "bpfilter/list.h"
#include "bpfilter/opts.h"
#include "harness/test.h"
#include "harness/test.h"
#include "bpfilter/helper.h"
#include "bpfilter/helper.h"
#include "harness/test.h"

#define _free_bf_test_opts_ __attribute__((cleanup(_bf_test_opts_free)))

typedef struct
{
    bf_test_filter *group_filter;
} bf_test_opts;

static struct argp_option _bf_test_options[] = {
    {"group", 'g', "REGEX", 0,
     "Regex to filter the test groups to run. If unused, all the test groups are executed.",
     0},
    {0},
};

static void _bf_test_opts_free(bf_test_opts **opts);

static error_t _bf_test_argp_cb(int key, char *arg, struct argp_state *state)
{
    bf_test_opts *opts = state->input;
    int r;

    switch (key) {
    case 'g':
        r = bf_test_filter_add_pattern(opts->group_filter, arg);
        if (r)
            return r;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int _bf_test_opts_new(bf_test_opts **opts, int argc, char *argv[])
{
    _free_bf_test_opts_ bf_test_opts *_opts = NULL;
    struct argp argp = {
        _bf_test_options, _bf_test_argp_cb, NULL, NULL, 0, NULL, NULL};
    int r;

    bf_assert(opts && argv);

    _opts = calloc(1, sizeof(*_opts));
    if (!_opts)
        return -ENOMEM;

    r = bf_test_filter_new(&_opts->group_filter);
    if (r)
        return r;

    r = argp_parse(&argp, argc, argv, 0, 0, _opts);
    if (r)
        return r;

    *opts = TAKE_PTR(_opts);

    return 0;
}

static void _bf_test_opts_free(bf_test_opts **opts)
{
    bf_assert(opts);

    if (!*opts)
        return;

    bf_test_filter_free(&(*opts)->group_filter);

    free(*opts);
    *opts = NULL;
}

int main(int argc, char *argv[])
{
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    _free_bf_test_opts_ bf_test_opts *opts = NULL;
    extern bf_test __start_bf_test;
    extern bf_test __stop_bf_test;
    int failed = 0;
    char *bf_opts[] = {
        argv[0],
        "--transient"
    };
    int r;

    r = _bf_test_opts_new(&opts, argc, argv);
    if (r) {
        fprintf(stderr, "failed to create a bf_test_opts object\n");
        return r;
    }

    // Ensure we run in transient mode, so unit tests won't pin BPF objects
    r = bf_opts_init(ARRAY_SIZE(bf_opts), bf_opts);
    if (r)
        return bf_err_r(r, "failed to enable transient mode for unit tests");

    r = bf_test_discover_test_suite(&suite, &__start_bf_test, &__stop_bf_test);
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
