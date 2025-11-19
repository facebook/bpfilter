/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/request.h"

#include <errno.h>
#include <string.h>

#include <bpfilter/dynbuf.h>
#include <bpfilter/pack.h>

#include "fake.h"
#include "test.h"

static void new_request(void **state)
{
    _free_bf_request_ struct bf_request *request = NULL;
    const char *data = "test data";
    size_t data_len = strlen(data) + 1;

    (void)state;

    // Create request with no data
    assert_ok(bf_request_new(&request, BF_FRONT_CLI, BF_REQ_CHAIN_GET, NULL, 0));
    assert_non_null(request);
    assert_int_equal(bf_request_front(request), BF_FRONT_CLI);
    assert_int_equal(bf_request_cmd(request), BF_REQ_CHAIN_GET);
    assert_int_equal(bf_request_data_len(request), 0);

    bf_request_free(&request);
    assert_null(request);

    // Create request with data
    assert_ok(bf_request_new(&request, BF_FRONT_IPT, BF_REQ_RULESET_SET, data,
                             data_len));
    assert_non_null(request);
    assert_int_equal(bf_request_front(request), BF_FRONT_IPT);
    assert_int_equal(bf_request_cmd(request), BF_REQ_RULESET_SET);
    assert_int_equal(bf_request_data_len(request), data_len);
    assert_string_equal(bf_request_data(request), data);
}

static void new_from_dynbuf(void **state)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_request_ struct bf_request *src = NULL;
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    const char *data = "dynbuf test data";
    size_t data_len = strlen(data) + 1;

    (void)state;

    // Create a source request to copy into dynbuf
    assert_ok(
        bf_request_new(&src, BF_FRONT_CLI, BF_REQ_CHAIN_SET, data, data_len));

    // Write request to dynbuf
    assert_ok(bf_dynbuf_write(&dynbuf, src, bf_request_size(src)));

    // Create request from dynbuf
    assert_ok(bf_request_new_from_dynbuf(&request, &dynbuf));
    assert_non_null(request);
    assert_int_equal(bf_request_front(request), BF_FRONT_CLI);
    assert_int_equal(bf_request_cmd(request), BF_REQ_CHAIN_SET);
    assert_int_equal(bf_request_data_len(request), data_len);
    assert_string_equal(bf_request_data(request), data);

    // dynbuf should now be empty after taking ownership
    assert_null(dynbuf.data);
}

static void new_from_dynbuf_invalid(void **state)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    char small_data[4] = {0};

    (void)state;

    // Too small dynbuf (less than sizeof(bf_request))
    assert_ok(bf_dynbuf_write(&dynbuf, small_data, sizeof(small_data)));
    assert_err(bf_request_new_from_dynbuf(&request, &dynbuf));
}

static void new_from_pack(void **state)
{
    _free_bf_request_ struct bf_request *request = NULL;
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const char *data = "packed data";

    (void)state;

    // Create and populate a pack
    assert_ok(bf_wpack_new(&pack));
    bf_wpack_kv_str(pack, "message", data);

    assert_true(bf_wpack_is_valid(pack));
    assert_ok(bf_request_new_from_pack(&request, BF_FRONT_CLI, BF_REQ_CUSTOM,
                                       pack));
    assert_non_null(request);
    assert_int_equal(bf_request_front(request), BF_FRONT_CLI);
    assert_int_equal(bf_request_cmd(request), BF_REQ_CUSTOM);
    assert_int_gt(bf_request_data_len(request), 0);
}

static void copy(void **state)
{
    _free_bf_request_ struct bf_request *src = NULL;
    _free_bf_request_ struct bf_request *dest = NULL;
    const char *data = "copy test data";
    size_t data_len = strlen(data) + 1;

    (void)state;

    // Copy request with data
    assert_ok(bf_request_new(&src, BF_FRONT_NFT, BF_REQ_CHAIN_LOAD, data,
                             data_len));
    assert_ok(bf_request_copy(&dest, src));

    assert_non_null(dest);
    assert_int_equal(bf_request_front(dest), bf_request_front(src));
    assert_int_equal(bf_request_cmd(dest), bf_request_cmd(src));
    assert_int_equal(bf_request_data_len(dest), bf_request_data_len(src));
    assert_int_equal(bf_request_size(dest), bf_request_size(src));
    assert_string_equal(bf_request_data(dest), bf_request_data(src));

    // Ensure it's a deep copy (different memory)
    assert_ptr_not_equal(dest, src);
    assert_ptr_not_equal(bf_request_data(dest), bf_request_data(src));
}

static void accessors(void **state)
{
    _free_bf_request_ struct bf_request *request = NULL;
    const char *data = "accessor test";
    size_t data_len = strlen(data) + 1;
    size_t expected_size;

    (void)state;

    assert_ok(bf_request_new(&request, BF_FRONT_CLI, BF_REQ_CHAIN_GET, data,
                             data_len));

    // Test bf_request_front
    assert_int_equal(bf_request_front(request), BF_FRONT_CLI);

    // Test bf_request_cmd
    assert_int_equal(bf_request_cmd(request), BF_REQ_CHAIN_GET);

    // Test bf_request_data
    assert_non_null(bf_request_data(request));
    assert_string_equal(bf_request_data(request), data);

    // Test bf_request_data_len
    assert_int_equal(bf_request_data_len(request), data_len);

    // Test bf_request_size (should be struct size + data_len)
    expected_size = bf_request_size(request);
    assert_int_gt(expected_size, data_len);

    // Test bf_request_ns (initially NULL)
    assert_null(bf_request_ns(request));

    // Test bf_request_fd (initially 0)
    assert_int_equal(bf_request_fd(request), 0);
}

static void setters(void **state)
{
    _free_bf_request_ struct bf_request *request = NULL;
    struct bf_ns *fake_ns = (struct bf_ns *)0xDEADBEEF;

    (void)state;

    assert_ok(bf_request_new(&request, BF_FRONT_CLI, BF_REQ_CHAIN_GET, NULL, 0));

    // Test bf_request_set_ns
    bf_request_set_ns(request, fake_ns);
    assert_ptr_equal(bf_request_ns(request), fake_ns);

    // Test bf_request_set_fd
    bf_request_set_fd(request, 42);
    assert_int_equal(bf_request_fd(request), 42);

    // Test bf_request_set_ipt_cmd
    bf_request_set_ipt_cmd(request, 123);
    assert_int_equal(bf_request_ipt_cmd(request), 123);
}

static void size_calculation(void **state)
{
    _free_bf_request_ struct bf_request *request1 = NULL;
    _free_bf_request_ struct bf_request *request2 = NULL;
    const char *small_data = "x";
    const char *large_data = "this is a much larger piece of data for testing";

    (void)state;

    assert_ok(bf_request_new(&request1, BF_FRONT_CLI, BF_REQ_CHAIN_GET,
                             small_data, strlen(small_data) + 1));
    assert_ok(bf_request_new(&request2, BF_FRONT_CLI, BF_REQ_CHAIN_GET,
                             large_data, strlen(large_data) + 1));

    // Larger data should result in larger size
    assert_int_gt(bf_request_size(request2), bf_request_size(request1));

    // Size difference should match data length difference
    size_t size_diff = bf_request_size(request2) - bf_request_size(request1);
    size_t data_diff =
        bf_request_data_len(request2) - bf_request_data_len(request1);
    assert_int_equal(size_diff, data_diff);
}

static void cmd_to_str(void **state)
{
    (void)state;

    // Test all command strings
    assert_non_null(bf_request_cmd_to_str(BF_REQ_RULESET_FLUSH));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_RULESET_GET));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_RULESET_SET));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_SET));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_GET));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_LOAD));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_ATTACH));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_UPDATE));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_PROG_FD));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_LOGS_FD));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CHAIN_FLUSH));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_COUNTERS_SET));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_COUNTERS_GET));
    assert_non_null(bf_request_cmd_to_str(BF_REQ_CUSTOM));

    // Verify specific strings
    assert_string_equal(bf_request_cmd_to_str(BF_REQ_CHAIN_GET),
                        "BF_REQ_CHAIN_GET");
    assert_string_equal(bf_request_cmd_to_str(BF_REQ_CUSTOM), "BF_REQ_CUSTOM");
}

static void free_null(void **state)
{
    struct bf_request *request = NULL;

    (void)state;

    // Freeing NULL pointer should not crash
    bf_request_free(&request);
    assert_null(request);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_request),
        cmocka_unit_test(new_from_dynbuf),
        cmocka_unit_test(new_from_dynbuf_invalid),
        cmocka_unit_test(new_from_pack),
        cmocka_unit_test(copy),
        cmocka_unit_test(accessors),
        cmocka_unit_test(setters),
        cmocka_unit_test(size_calculation),
        cmocka_unit_test(cmd_to_str),
        cmocka_unit_test(free_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
