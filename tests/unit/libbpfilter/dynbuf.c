/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/dynbuf.h>
#include <bpfilter/helper.h>

#include "test.h"

#define BFT_DYNBUF_WRITE_REPEAT 1 << 16
#define BFT_DYNBUF_WRITE_SIZE 64

static void init_and_clean(void **state)
{
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf;

    (void)state;

    // Free dynbuf manually
    dynbuf = bf_dynbuf_default();
    assert_int_equal(dynbuf.len, 0);
    assert_int_equal(dynbuf.rem, 0);
    assert_null(dynbuf.data);
    assert_ok(bf_dynbuf_write(&dynbuf, "hello", 5)); // Write fake data
    bf_dynbuf_clean(&dynbuf);

    // Free dynbuf automatically
    dynbuf = bf_dynbuf_default();
    assert_int_equal(dynbuf.len, 0);
    assert_int_equal(dynbuf.rem, 0);
    assert_null(dynbuf.data);
    assert_ok(bf_dynbuf_write(&dynbuf, "hello", 5)); // Write fake data
}

static void write_and_grow(void **state)
{
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    uint8_t data[BFT_DYNBUF_WRITE_SIZE] = {};

    (void)state;

    for (int i = 0; i < BFT_DYNBUF_WRITE_REPEAT; ++i)
        assert_ok(bf_dynbuf_write(&dynbuf, data, ARRAY_SIZE(data)));

    assert_int_equal(dynbuf.len,
                     BFT_DYNBUF_WRITE_SIZE * BFT_DYNBUF_WRITE_REPEAT);
}

static void take(void **state)
{
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    _cleanup_free_ void *stolen_data = NULL;
    uint8_t data[BFT_DYNBUF_WRITE_SIZE] = {};

    (void)state;

    // Create predictable data
    for (int i = 0; i < BFT_DYNBUF_WRITE_SIZE; ++i)
        data[i] = i;

    assert_ok(bf_dynbuf_write(&dynbuf, data, ARRAY_SIZE(data)));
    assert_non_null(stolen_data = bf_dynbuf_take(&dynbuf));

    assert_memory_equal(stolen_data, data, BFT_DYNBUF_WRITE_SIZE);
    assert_int_equal(dynbuf.len, 0);
    assert_int_equal(dynbuf.rem, 0);
    assert_null(dynbuf.data);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(init_and_clean),
        cmocka_unit_test(write_and_grow),
        cmocka_unit_test(take),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
