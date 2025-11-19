/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <limits.h>

#include <bpfilter/counter.h>

#include "bpfilter/pack.h"
#include "fake.h"
#include "test.h"

#define BFT_COUNTER_PKTS 4
#define BFT_COUNTER_BYTES 3190

static void new_and_free(void **state)
{
    _free_bf_counter_ struct bf_counter *counter = NULL;

    (void)state;

    // Free counters manually
    assert_ok(bf_counter_new(&counter, BFT_COUNTER_PKTS, BFT_COUNTER_BYTES));
    assert_int_equal(counter->packets, BFT_COUNTER_PKTS);
    assert_int_equal(counter->bytes, BFT_COUNTER_BYTES);
    bf_counter_free(&counter);
    assert_null(counter);

    // Free counters using the cleanup attribute
    assert_ok(bf_counter_new(&counter, BFT_COUNTER_PKTS, BFT_COUNTER_BYTES));
    assert_int_equal(counter->packets, BFT_COUNTER_PKTS);
    assert_int_equal(counter->bytes, BFT_COUNTER_BYTES);
}

static void pack_and_unpack(void **state)
{
    _free_bf_counter_ struct bf_counter *source = NULL;
    _free_bf_counter_ struct bf_counter *destination = NULL;
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    bf_rpack_node_t node;
    const void *data;
    size_t data_len;

    (void)state;

    // Pack the source counter
    assert_ok(bf_counter_new(&source, BFT_COUNTER_PKTS, BFT_COUNTER_BYTES));
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "counter");
    assert_ok(bf_counter_pack(source, wpack));
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Unpack in the destination counter
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_ok(bf_rpack_kv_obj(bf_rpack_root(rpack), "counter", &node));
    assert_ok(bf_counter_new_from_pack(&destination, node));

    assert_true(bft_counter_eq(source, destination));
}

static void unpack_error(void **state)
{
    (void)state;

    {
        // Missing `packets` field

        _free_bf_counter_ struct bf_counter *destination = NULL;
        _free_bf_wpack_ bf_wpack_t *wpack = NULL;
        _free_bf_rpack_ bf_rpack_t *rpack = NULL;
        const void *data;
        size_t data_len;

        assert_ok(bf_wpack_new(&wpack));
        bf_wpack_kv_u64(wpack, "packets", BFT_COUNTER_PKTS);
        assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

        assert_ok(bf_rpack_new(&rpack, data, data_len));
        assert_err(
            bf_counter_new_from_pack(&destination, bf_rpack_root(rpack)));
    }

    {
        // Missing `bytes` field

        _free_bf_counter_ struct bf_counter *destination = NULL;
        _free_bf_wpack_ bf_wpack_t *wpack = NULL;
        _free_bf_rpack_ bf_rpack_t *rpack = NULL;
        const void *data;
        size_t data_len;

        assert_ok(bf_wpack_new(&wpack));
        bf_wpack_kv_u64(wpack, "bytes", BFT_COUNTER_BYTES);
        assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

        assert_ok(bf_rpack_new(&rpack, data, data_len));
        assert_err(
            bf_counter_new_from_pack(&destination, bf_rpack_root(rpack)));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_and_free),
        cmocka_unit_test(pack_and_unpack),
        cmocka_unit_test(unpack_error),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
