/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/hook.c"

#include "harness/cmocka.h"
#include "harness/mock.h"

Test(hook, hook_to_str_to_hook)
{
    enum bf_hook hook;

    expect_assert_failure(bf_hook_to_str(-1));
    expect_assert_failure(bf_hook_to_str(_BF_HOOK_MAX));
    expect_assert_failure(bf_hook_from_str(NULL, NOT_NULL));
    expect_assert_failure(bf_hook_from_str(NOT_NULL, NULL));

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        const char *str = bf_hook_to_str(i);

        assert_non_null(str);
        assert_int_not_equal(-1, bf_hook_from_str(str, &hook));
        assert_int_equal(hook, i);
    }

    assert_int_not_equal(0, bf_hook_from_str("", &hook));
    assert_int_not_equal(0, bf_hook_from_str("invalid", &hook));
}

Test(hook, hook_to_bpf_prog_type_assert_failure)
{
    expect_assert_failure(bf_hook_to_bpf_prog_type(-1));
    expect_assert_failure(bf_hook_to_bpf_prog_type(_BF_HOOK_MAX));
}

Test(hook, can_get_prog_type_from_hook)
{
    for (int i = 0; i < _BF_HOOK_MAX; ++i)
        assert_true(bf_hook_to_bpf_prog_type(i) <= BPF_PROG_TYPE_NETFILTER);
}

Test(hook, hook_to_flavor_assert_failure)
{
    expect_assert_failure(bf_hook_to_flavor(-1));
    expect_assert_failure(bf_hook_to_flavor(_BF_HOOK_MAX));
}

Test(hook, can_get_flavor_from_hook)
{
    enum bf_flavor flavor;

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        flavor = bf_hook_to_flavor(i);
        assert_true(0 <= flavor);
        assert_true(flavor < _BF_FLAVOR_MAX);
    }
}

Test(hook, hook_to_attach_type_assert_failure)
{
    expect_assert_failure(bf_hook_to_attach_type(-1));
    expect_assert_failure(bf_hook_to_attach_type(_BF_HOOK_MAX));
}

Test(hook, can_get_attach_type_from_hook)
{
    enum bpf_attach_type attach_type;

    for (int i = 0; i < _BF_HOOK_MAX; ++i) {
        attach_type = bf_hook_to_attach_type(i);
        assert_true(0 <= attach_type);
        // Don't check if the attach_type is a valid bpf_attach_type for the
        // current kernel, as we might define it in compat.h to allow bpfilter
        // to build.
    }
}
