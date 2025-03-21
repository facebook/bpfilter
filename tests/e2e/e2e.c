/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "e2e.h"

#include <linux/pkt_cls.h>

#include "bpfilter.h"
#include "opts.h"
#include "core/bpf.h"
#include "core/logger.h"
#include "harness/daemon.h"
#include "harness/test.h"

static int _bf_progtype_verdict[_BF_HOOK_MAX][2] = {
    [BF_HOOK_XDP] = {
        [BF_VERDICT_ACCEPT] = XDP_PASS,
        [BF_VERDICT_DROP] = XDP_DROP,
    },
    [BF_HOOK_TC_INGRESS] = {
        [BF_VERDICT_ACCEPT] = TC_ACT_OK,
        [BF_VERDICT_DROP] = TC_ACT_SHOT,
    },
    [BF_HOOK_NF_PRE_ROUTING] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_NF_LOCAL_IN] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_NF_FORWARD] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_CGROUP_INGRESS] = {
        [BF_VERDICT_ACCEPT] = SK_PASS,
        [BF_VERDICT_DROP] = SK_DROP,
    },
    [BF_HOOK_CGROUP_EGRESS] = {
        [BF_VERDICT_ACCEPT] = SK_PASS,
        [BF_VERDICT_DROP] = SK_DROP,
    },
    [BF_HOOK_NF_LOCAL_OUT] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_NF_POST_ROUTING] = {
        [BF_VERDICT_ACCEPT] = NF_ACCEPT,
        [BF_VERDICT_DROP] = NF_DROP,
    },
    [BF_HOOK_TC_EGRESS] = {
        [BF_VERDICT_ACCEPT] = TC_ACT_OK,
        [BF_VERDICT_DROP] = TC_ACT_SHOT,
    },
};

int bft_e2e_test(struct bf_chain *chain, enum bf_verdict expect,
                 const struct bft_prog_run_args *args)
{
    _cleanup_bf_test_daemon_ struct bf_test_daemon daemon = bft_daemon_default();
    bool success = true, daemon_failure = false;
    int retval[_BF_HOOK_MAX] = {};
    int r;

    bf_assert(chain && args);

    r = bf_test_daemon_init(&daemon, bft_e2e_bpfilter_path(),
                            BF_TEST_DAEMON_TRANSIENT |
                            BF_TEST_DAEMON_NO_IPTABLES |
                            BF_TEST_DAEMON_NO_NFTABLES);
    if (r < 0)
        return bf_err_r(r, "failed to create the bpfilter daemon");

    r = bf_test_daemon_start(&daemon);
    if (r < 0)
        return bf_err_r(r, "failed to start the bpfilter daemon");

    for (enum bf_hook hook = BF_HOOK_XDP; hook < _BF_HOOK_MAX; ++hook) {
        _free_bf_test_prog_ struct bf_test_prog *prog = NULL;
        const struct bft_prog_run_args *arg = &args[hook];
        int test_ret;

        chain->hook = hook;
        prog = bf_test_prog_get(chain);
        if (!prog) {
            bf_err("failed to get the test program");
            daemon_failure = true;
            break;
        }

        test_ret = bf_prog_run(prog->fd, arg->pkt, arg->pkt_len,
                               arg->ctx_len ? &arg->ctx : NULL, arg->ctx_len);
        if (test_ret < 0) {
            bf_err_r(test_ret, "failed to run the program");
            daemon_failure = true;
            break;
        }

        bf_cli_ruleset_flush();

        retval[hook] = test_ret;
    }

    r = bf_test_daemon_stop(&daemon);
    if (r < 0)
        return bf_err_r(r, "failed to stop the bpfilter daemon");

    if (daemon_failure) {
        _cleanup_free_ const char *err = bf_test_process_stderr(&daemon.process);
        bf_info("stderr:\n%s", err);
        fail();
    }

    for (enum bf_hook hook = BF_HOOK_XDP; hook < _BF_HOOK_MAX; ++hook) {
        if (_bf_progtype_verdict[hook][expect] == retval[hook])
            continue;

        // Not ideal, but at least it's properly formatted
        print_error("%sERROR: %s: BPF_PROG_RUN returned %d, expecting %d\n",
                    "             ", bf_hook_to_str(hook), retval[hook],
                    _bf_progtype_verdict[chain->hook][expect]);
        success = false;
    }

    if (!success)
        fail();

    return 0;
}
