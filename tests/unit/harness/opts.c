/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/opts.h"

#include <argp.h>

#include "harness/filter.h"
#include "shared/helper.h"

static struct argp_option _bf_test_options[] = {
    {"group", 'g', "REGEX", 0,
     "Regex to filter the test groups to run. If unused, all the test groups are executed.",
     0},
    {0},
};

static error_t _bf_test_argp_cb(int key, char *arg, struct argp_state *state)
{
    struct bf_test_opts *opts = state->input;
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

int bf_test_opts_new(struct bf_test_opts **opts, int argc, char *argv[])
{
    _cleanup_bf_test_opts_ struct bf_test_opts *_opts = NULL;
    struct argp argp = {
        _bf_test_options, _bf_test_argp_cb, NULL, NULL, 0, NULL, NULL};
    int r;

    bf_assert(opts);
    bf_assert(argv);

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

void bf_test_opts_free(struct bf_test_opts **opts)
{
    bf_assert(opts);

    if (!*opts)
        return;

    bf_test_filter_free(&(*opts)->group_filter);

    free(*opts);
    *opts = NULL;
}
