/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpf/btf.h>
#include <limits.h>

#include <bpfilter/btf.h>

#include "mock.h"
#include "test.h"

static void load_failure(void **state)
{
    _clean_bft_mock_ bft_mock _ = bft_mock_get(btf__load_vmlinux_btf);

    (void)state;

    assert_null(btf__load_vmlinux_btf());
}

static void get_id_and_name(void **state)
{
    struct btf *btf;
    int id;

    (void)state;

    btf = btf__load_vmlinux_btf();
    assert_non_null(btf);

    // Unknown type
    assert_err(bf_btf_get_id(btf, "les carottes sont cuites"));

    id = bf_btf_get_id(btf, "sk_buff");
    assert_int_gte(id, 0);

    assert_string_equal(bf_btf_get_name(btf, id), "sk_buff");

    assert_null(bf_btf_get_name(btf, -1));
    assert_null(bf_btf_get_name(btf, INT_MAX));

    btf__free(btf);
}

static void check_token(void **state)
{
    struct btf *btf;

    (void)state;

    btf = btf__load_vmlinux_btf();
    assert_non_null(btf);

    /* Ignore the return value, as the expected result depends on the
     * current kernel version, but trigger the code path anyway. */
    bf_btf_kernel_has_token(btf);

    btf__free(btf);
}

static void get_field_offset(void **state)
{
    struct btf *btf;

    (void)state;

    btf = btf__load_vmlinux_btf();
    assert_non_null(btf);

    assert_int_gte(bf_btf_get_field_off(btf, "sk_buff", "sk"), 0);

    // Nested in anonymous union/structs
    assert_int_equal(bf_btf_get_field_off(btf, "sk_buff", "next"), 0);
    assert_int_equal(bf_btf_get_field_off(btf, "sk_buff", "prev"),
                     sizeof(void *));
    assert_int_equal(bf_btf_get_field_off(btf, "sk_buff", "dev"),
                     2 * sizeof(void *));

    // Invalid compound type
    assert_err(bf_btf_get_field_off(btf, "les carottes", "sont cuites"));

    // Invalid field
    assert_err(bf_btf_get_field_off(btf, "sk_buff", "sont cuites"));

    // Bitfield are not supported
    assert_err(bf_btf_get_field_off(btf, "tcphdr", "syn"));

    btf__free(btf);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(load_failure),
        cmocka_unit_test(get_id_and_name),
        cmocka_unit_test(check_token),
        cmocka_unit_test(get_field_offset),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
