/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/hook.c"

#include "harness/test.h"
#include "mock.h"

Test(hook, hook_to_str_and_back)
{
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook) {
        const char *str = bf_hook_to_str(hook);
        assert_non_null(str);
    }

    expect_assert_failure(bf_hook_from_str(NULL));
    assert_error(bf_hook_from_str(""));
    assert_error(bf_hook_from_str("BF_HOOK_XD"));
    assert_error(bf_hook_from_str("no"));
}

Test(hook, hook_to_flavor)
{
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook)
        bf_hook_to_flavor(hook);
}

Test(hook, hook_to_bpf_attach_type)
{
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook)
        bf_hook_to_bpf_attach_type(hook);
}

Test(hook, hook_to_bpf_prog_type)
{
    for (enum bf_hook hook = 0; hook < _BF_HOOK_MAX; ++hook)
        bf_hook_to_bpf_prog_type(hook);
}

Test(hook, hook_to_nfhook_and_back)
{
    for (enum bf_nf_inet_hooks hook = 0; hook < BF_NF_INET_NUMHOOKS; ++hook) {
        enum bf_hook bfhook = bf_hook_from_nf_hook(hook);
        assert_int_equal(bf_hook_to_nf_hook(bfhook), hook);
        assert_non_null(bf_nf_hook_to_str(hook));
    }

    assert_error(bf_hook_to_nf_hook(BF_HOOK_XDP));
    assert_error(bf_hook_to_nf_hook(BF_HOOK_TC_INGRESS));
    assert_error(bf_hook_from_nf_hook(-1));
}

Test(hook, parse_family)
{
    struct bf_hookopts opts = {};
    struct bf_hookopts_ops *ops = &_bf_hookopts_ops[BF_HOOKOPTS_FAMILY];

    expect_assert_failure(ops->parse(NULL, NOT_NULL));
    expect_assert_failure(ops->parse(NOT_NULL, NULL));
    expect_assert_failure(ops->parse(NULL, NULL));

    assert_error(ops->parse(&opts, "inet"));
    assert_error(ops->parse(&opts, "ine6"));
    assert_int_equal(opts.family, 0);
    assert_success(ops->parse(&opts, "inet4"));
    assert_int_equal(opts.family, PF_INET);
    assert_success(ops->parse(&opts, "inet6"));
    assert_int_equal(opts.family, PF_INET6);
}

Test(hook, parse_priorities)
{
    struct bf_hookopts opts = {};
    struct bf_hookopts_ops *ops = &_bf_hookopts_ops[BF_HOOKOPTS_PRIORITIES];

    expect_assert_failure(ops->parse(NULL, NOT_NULL));
    expect_assert_failure(ops->parse(NOT_NULL, NULL));
    expect_assert_failure(ops->parse(NULL, NULL));

    assert_error(ops->parse(&opts, "1"));
    assert_error(ops->parse(&opts, "1-"));
    assert_error(ops->parse(&opts, "1-a"));
    assert_error(ops->parse(&opts, "a-1"));
    assert_error(ops->parse(&opts, "-1"));
    assert_error(ops->parse(&opts, "1-1"));
    assert_error(ops->parse(&opts, "1-0"));
    assert_error(ops->parse(&opts, "0-1"));
    assert_int_equal(opts.priorities[0], 0);
    assert_int_equal(opts.priorities[1], 0);

    assert_success(ops->parse(&opts, "100-101"));
    assert_int_equal(opts.priorities[0], 100);
    assert_int_equal(opts.priorities[1], 101);
    assert_success(ops->parse(&opts, "101-100"));
    assert_int_equal(opts.priorities[0], 101);
    assert_int_equal(opts.priorities[1], 100);
    assert_success(ops->parse(&opts, "1-2"));
    assert_int_equal(opts.priorities[0], 1);
    assert_int_equal(opts.priorities[1], 2);
}
