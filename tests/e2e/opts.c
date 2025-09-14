/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "opts.h"

#include <linux/limits.h>

#include <argp.h>

#include "bpfilter/helper.h"

static struct
{
    char bpfilter_path[PATH_MAX];
} _bf_opts = {
    .bpfilter_path = "bpfilter",
};

static struct argp_option _bf_e2e_options[] = {
    {"bpfilter", 'b', "BPFILTER", 0,
     "Path to the bpfilter daemon binary. Defaults to 'bpfilter' in PATH", 0},
    {0},
};

static error_t _bf_e2e_argp_cb(int key, char *arg, struct argp_state *state)
{
    UNUSED(state);

    switch (key) {
    case 'b':
        bf_strncpy(_bf_opts.bpfilter_path, PATH_MAX, arg);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int bft_e2e_parse_args(int argc, char *argv[])
{
    struct argp argp = { _bf_e2e_options, _bf_e2e_argp_cb, NULL, NULL, 0, NULL, NULL};

    return -argp_parse(&argp, argc, argv, 0, 0, NULL);
}

const char *bft_e2e_bpfilter_path(void)
{
    return _bf_opts.bpfilter_path;
}
