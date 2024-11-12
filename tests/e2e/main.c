/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <argp.h>

#include "core/logger.h"
#include "harness/daemon.h"
#include "harness/filters.h"
#include "harness/prog.h"
#include "harness/test.h"
#include "libbpfilter/bpfilter.h"
#include "packets.h"

struct bf_e2e_opts
{
    const char *bpfilter_path;
};

static struct argp_option _bf_e2e_options[] = {
    {"bpfilter", 'b', "BPFILTER", 0,
     "Path to the bpfilter daemon binary. Defaults to 'bpfilter' in PATH", 0},
    {0},
};

static error_t _bf_e2e_argp_cb(int key, char *arg, struct argp_state *state)
{
    struct bf_e2e_opts *opts = state->input;

    switch (key) {
    case 'b':
        if (opts->bpfilter_path) {
            bf_warn("--bpfilter is already set, replacing existing value");
            freep(&opts->bpfilter_path);
        }

        opts->bpfilter_path = strdup(arg);
        if (!opts->bpfilter_path)
            return bf_err_r(errno, "failed to copy --bpfilter argument");
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

#define _clean_bf_e2e_opts_ __attribute__((__cleanup__(_bf_e2e_opts_clean)))

static void _bf_e2e_opts_clean(struct bf_e2e_opts *opts)
{
    if (!opts)
        return;

    freep((void *)&opts->bpfilter_path);
}

Test(xdp, default_policy)
{
    _cleanup_bf_chain_ struct bf_chain *chain = bf_chain_get(
        BF_HOOK_XDP,
        bf_hook_opts_get(
            BF_HOOK_OPT_IFINDEX, 2,
            BF_HOOK_OPT_NAME, "bf_e2e_testprog",
            BF_HOOK_OPT_ATTACH, false,
            -1
        ),
        BF_VERDICT_ACCEPT,
        NULL,
        (struct bf_rule *[]) {
            NULL,
        }
    );
    _free_bf_test_prog_ struct bf_test_prog *prog = NULL;

    if (bf_cli_set_chain(chain) < 0)
        bf_test_fail("failed to send the chain to the daemon");

    assert_non_null(prog = bf_test_prog_get("bf_e2e_testprog"));
    assert_success(bf_test_prog_run(prog, 2, pkt_local_ip6_tcp));
}

int main(int argc, char *argv[])
{
    _free_bf_test_suite_ bf_test_suite *suite = NULL;
    _clean_bf_e2e_opts_ struct bf_e2e_opts opts = {};
    struct argp argp = { _bf_e2e_options, _bf_e2e_argp_cb, NULL, NULL, 0, NULL, NULL};
    int failed = 0;
    int r;

    r = argp_parse(&argp, argc, argv, 0, 0, &opts);
    if (r)
        return r;

    r = bf_test_discover_test_suite(&suite);
    if (r < 0)
        return bf_err_r(r, "test suite discovery failed");

    bf_list_foreach (&suite->groups, group_node) {
        _cleanup_bf_test_daemon_ struct bf_test_daemon daemon;
        bf_test_group *group = bf_list_node_get_data(group_node);

        r = bf_test_daemon_init(&daemon, opts.bpfilter_path ?: "bpfilter",
                                BF_TEST_DAEMON_TRANSIENT |
                                BF_TEST_DAEMON_NO_IPTABLES |
                                BF_TEST_DAEMON_NO_NFTABLES);
        if (r < 0)
            return bf_err_r(r, "failed to create the bpfiler daemon");

        r = bf_test_daemon_start(&daemon);
        if (r < 0)
            return bf_err_r(r, "failed to start the bpfilter daemon");

        r = _cmocka_run_group_tests(group->name, group->cmtests,
                                    bf_list_size(&group->tests), NULL, NULL);
        if (r)
            failed = 1;

        r = bf_test_daemon_stop(&daemon);
        if (r < 0)
            return bf_err_r(r, "failed to stop the bpfilter daemon");
    }

    if (failed)
        fail_msg("At least one test group failed!");

    return 0;
}
