/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "e2e.h"

#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include "bpfilter/bpfilter.h"
#include "opts.h"
#include "bpfilter/bpf.h"
#include "bpfilter/chain.h"
#include "bpfilter/flavor.h"
#include "bpfilter/logger.h"
#include "harness/daemon.h"
#include "harness/test.h"

static struct {
    enum bf_hook hook;
    int verdicts[2];
} _bf_tests_meta[_BF_FLAVOR_MAX] = {
    [BF_FLAVOR_TC] = {
        .hook = BF_HOOK_TC_EGRESS,
        .verdicts = {
            [BF_VERDICT_ACCEPT] = TC_ACT_OK,
            [BF_VERDICT_DROP] = TC_ACT_SHOT,
        },
    },
    [BF_FLAVOR_NF] = {
        .hook = BF_HOOK_NF_POST_ROUTING,
        .verdicts = {
            [BF_VERDICT_ACCEPT] = NF_ACCEPT,
            [BF_VERDICT_DROP] = NF_DROP,
        },
    },
    [BF_FLAVOR_XDP] = {
        .hook = BF_HOOK_XDP,
        .verdicts = {
            [BF_VERDICT_ACCEPT] = XDP_PASS,
            [BF_VERDICT_DROP] = XDP_DROP,
        },
    },
    [BF_FLAVOR_CGROUP] = {
        .hook = BF_HOOK_CGROUP_INGRESS,
        .verdicts = {
            [BF_VERDICT_ACCEPT] = SK_PASS,
            [BF_VERDICT_DROP] = SK_DROP,
        },
    },
};

static int _bft_e2e_test_with_counter(struct bf_chain *chain,
                                      enum bf_verdict expect,
                                      const struct bft_prog_run_args *args,
                                      const struct bft_counter *counter)
{
    _clean_bf_test_daemon_ struct bf_test_daemon daemon = bft_daemon_default();
    bool success = true, daemon_failure = false;
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

    for (enum bf_flavor flavor = 0; flavor < _BF_FLAVOR_MAX; ++flavor) {
        const struct bft_prog_run_args *arg = &args[flavor];
        _clean_bf_list_ bf_list counters = bf_list_default(bf_counter_free, NULL);
        _free_bf_chain_ struct bf_chain *_0 = NULL;
        _free_bf_hookopts_ struct bf_hookopts *_1 = NULL;
        _cleanup_close_ int fd = -1;
        int test_ret;

        chain->hook = _bf_tests_meta[flavor].hook;
        
        /* Skip the test for the current hook if the change doesn't validate.
         * The chain should be valid, but we run the test for every hook, so
         * if one of the features use is incompatible with the current hook
         * the validate fails. */
        if (!bf_chain_validate(chain))
            continue;
        
        r = bf_chain_load(chain);
        if (r) {
            bf_info("failed to load test chain");
            daemon_failure = true;
            break;
        }

        fd = bf_chain_prog_fd(chain->name);
        if (fd < 0) {
            bf_info("failed to get the test chain program FD");
            daemon_failure = true;
            break;
        }

        test_ret = bf_bpf_prog_run(fd, arg->pkt, arg->pkt_len,
                               arg->ctx_len ? &arg->ctx : NULL, arg->ctx_len);
        if (test_ret < 0) {
            bf_err_r(test_ret, "failed to run the program");
            daemon_failure = true;
            break;
        }

        r = bf_chain_get(chain->name, &_0, &_1, &counters);
        if (r) {
            bf_info("failed to retrieve chain 'bf_test'");
            daemon_failure = true;
            break;
        }

        bf_ruleset_flush();

        if (_bf_tests_meta[flavor].verdicts[expect] != test_ret) {
            print_error("%sERROR: %s: BPF_PROG_RUN returned %d, expecting %d\n",
                        "             ", bf_flavor_to_str(flavor), test_ret,
                        _bf_tests_meta[flavor].verdicts[expect]);
            success = false;
        }

        if (counter) {
            const struct bf_counter *ref = &counter->counter;
            const struct bf_counter *test;

            test = bf_list_get_at(&counters, counter->index);
            if (!test) {
                print_error("%sERROR: %s: missing counters for index %lu\n",
                            "             ",
                            bf_flavor_to_str(flavor), counter->index);
                success = false;
            }

            if (test && ref->packets != BFT_NO_PKTS && ref->packets != test->packets) {
                print_error("%sERROR: %s: rule #%lu: expecting %lu packets, got %lu\n",
                            "             ", bf_flavor_to_str(flavor),
                            counter->index, ref->packets, test->packets);
                success = false;
            }

            if (test && ref->bytes != BFT_NO_BYTES && ref->bytes != test->bytes) {
                print_error("%sERROR: %s: rule #%lu: expecting %lu bytes, got %lu\n",
                            "             ", bf_flavor_to_str(flavor),
                            counter->index, ref->bytes, test->bytes);
                success = false;
            }
        }
    }

    r = bf_test_daemon_stop(&daemon);
    if (r < 0)
        return bf_err_r(r, "failed to stop the bpfilter daemon");

    if (daemon_failure) {
        _cleanup_free_ const char *err = bf_test_process_stderr(&daemon.process);
        bf_info("stderr:\n%s", err);
        fail();
    }

    if (!success)
        fail();

    return 0;
}

int bft_e2e_test_with_counter(struct bf_chain *chain, enum bf_verdict expect,
    const struct bft_prog_run_args *args, const struct bft_counter *counter)
{
    return _bft_e2e_test_with_counter(chain, expect, args, counter);
}

int bft_e2e_test(struct bf_chain *chain, enum bf_verdict expect,
                 const struct bft_prog_run_args *args)
{
    return _bft_e2e_test_with_counter(chain, expect, args, NULL);
}
