/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/dump.h>

#include "fake.h"
#include "test.h"

static void push_pop_last(void **state)
{
    prefix_t prefix = {};

    (void)state;

    /* There is no need to validate the symbols used in the prefix string,
     * as the dump is mostly used for debugging (borched symbols are not
     * worth the testing effort). */

    // Do not underrun the buffer
    bf_dump_prefix_pop(&prefix);

    // Don't overrun it either
    for (int i = 0; i < DUMP_PREFIX_LEN; ++i)
        bf_dump_prefix_push(&prefix);

    // Prefix is full
    assert_non_null(bf_dump_prefix_last(&prefix));

    // Pop from non-empty, then push a last symbol
    bf_dump_prefix_pop(&prefix);
    assert_non_null(bf_dump_prefix_last(&prefix));
}

static void dump_hex(void **state)
{
    struct bft_streams *streams = *(struct bft_streams **)state;
    uint8_t single_line0[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t single_line1[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t two_lines[] = {0x01, 0x02, 0x03, 0x04, 0x05,
                           0x06, 0x07, 0x08, 0x09};
    prefix_t prefix = {};

    bf_dump_hex(&prefix, single_line0, ARRAY_SIZE(single_line0));
    bft_streams_flush(streams);
    assert_string_equal(streams->stderr_buf, "debug  : 0x01 0x02 0x03 0x04 \n");

    bf_dump_hex(&prefix, single_line1, ARRAY_SIZE(single_line1));
    bft_streams_flush(streams);
    assert_string_equal(streams->stderr_buf,
                        "debug  : 0x01 0x02 0x03 0x04 \n"
                        "debug  : 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 \n");

    bf_dump_hex(&prefix, two_lines, ARRAY_SIZE(two_lines));
    bft_streams_flush(streams);
    assert_string_equal(streams->stderr_buf,
                        "debug  : 0x01 0x02 0x03 0x04 \n"
                        "debug  : 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 \n"
                        "debug  : 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 \n"
                        "debug  : 0x09 \n");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(push_pop_last),
        cmocka_unit_test_setup_teardown(dump_hex, btf_setup_redirect_streams,
                                        bft_teardown_redirect_streams),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
