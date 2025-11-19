/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <limits.h>

#include <bpfilter/btf.h>

#include "mock.h"
#include "test.h"

static void init_and_clean(void **state)
{
    (void)state;

    {
        _clean_bft_mock_ bft_mock _ = bft_mock_get(btf__load_vmlinux_btf);

        assert_err(bf_btf_setup());
    }

    assert_ok(bf_btf_setup());
    bf_btf_teardown();
    assert_ok(bf_btf_setup());
    bf_btf_teardown();
}

static void get_id_and_name(void **state)
{
    int id;

    (void)state;

    assert_ok(bf_btf_setup());

    // Unknown type
    assert_err(bf_btf_get_id("les carottes sont cuites"));

    id = bf_btf_get_id("sk_buff");
    assert_int_gte(id, 0);

    assert_string_equal(bf_btf_get_name(id), "sk_buff");

    assert_null(bf_btf_get_name(-1));
    assert_null(bf_btf_get_name(INT_MAX));

    bf_btf_teardown();
}

static void check_token(void **state)
{
    (void)state;

    assert_ok(bf_btf_setup());

    /* Ignore the return value, has the expected result depends on the current
     * kernel version, but trigger the code path anyway. */
    bf_btf_kernel_has_token();

    bf_btf_teardown();
}

static void get_field_offset(void **state)
{
    (void)state;

    assert_ok(bf_btf_setup());

    assert_int_gte(bf_btf_get_field_off("sk_buff", "sk"), 0);

    // Nested in anonymous union/structs
    assert_int_equal(bf_btf_get_field_off("sk_buff", "next"), 0);
    assert_int_equal(bf_btf_get_field_off("sk_buff", "prev"), sizeof(void *));
    assert_int_equal(bf_btf_get_field_off("sk_buff", "dev"),
                     2 * sizeof(void *));

    // Invalid compound type
    assert_err(bf_btf_get_field_off("les carottes", "sont cuites"));

    // Invalid field
    assert_err(bf_btf_get_field_off("sk_buff", "sont cuites"));

    // Bitfield are not supported
    assert_err(bf_btf_get_field_off("tcphdr", "syn"));

    bf_btf_teardown();
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(get_id_and_name),
        cmocka_unit_test(check_token),
        cmocka_unit_test(get_field_offset),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
