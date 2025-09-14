/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/btf.c"

#include "harness/test.h"
#include "mock.h"

Test(btf, init)
{
    assert_success(bf_btf_setup());
    assert_non_null(_bf_btf);

    bf_btf_teardown();
    assert_null(_bf_btf);
}

Test(btf, failed_init)
{
    _clean_bf_test_mock_ bf_test_mock _ = bf_test_mock_get(btf__load_vmlinux_btf, NULL);

    assert_null(_bf_btf);
    assert_error(bf_btf_setup());
    assert_null(_bf_btf);
}

Test(btf, get_field_offset)
{
    assert_success(bf_btf_setup());

    assert_success(bf_btf_get_field_off("iphdr", "ihl"));
    assert_int_equal(9, bf_btf_get_field_off("iphdr", "protocol"));
    assert_int_equal(8, bf_btf_get_field_off("bpf_nf_ctx", "skb"));

    // Not a structure
    assert_true(bf_btf_get_field_off("long unsigned int", "protocol") < 0);

    // Invalid structure
    assert_true(bf_btf_get_field_off("ipheader", "protocol") < 0);

    // Invalid field
    assert_true(bf_btf_get_field_off("iphdr", "protocole") < 0);

    bf_btf_teardown();
}
