/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/response.h"

#include <errno.h>
#include <string.h>

#include <bpfilter/dynbuf.h>
#include <bpfilter/pack.h>

#include "fake.h"
#include "test.h"

static void new_raw(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;

    (void)state;

    assert_ok(bf_response_new_raw(&response, 0));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), 0);

    bf_response_free(&response);
    assert_null(response);

    assert_ok(bf_response_new_raw(&response, 1024));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), 0);
}

static void new_success(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;
    const char *data = "test data";
    size_t data_len = strlen(data) + 1;

    (void)state;

    // Success with no data
    assert_ok(bf_response_new_success(&response, NULL, 0));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), 0);
    assert_int_equal(bf_response_data_len(response), 0);

    bf_response_free(&response);
    assert_null(response);

    // Success with data
    assert_ok(bf_response_new_success(&response, data, data_len));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), 0);
    assert_int_equal(bf_response_data_len(response), data_len);
    assert_string_equal(bf_response_data(response), data);
}

static void new_from_dynbuf(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_response_ struct bf_response *src = NULL;
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    const char *data = "test data from dynbuf";
    size_t data_len = strlen(data) + 1;

    (void)state;

    // Create a source response to copy into dynbuf
    assert_ok(bf_response_new_success(&src, data, data_len));

    // Write response to dynbuf
    assert_ok(bf_dynbuf_write(&dynbuf, src, bf_response_size(src)));

    // Create response from dynbuf
    assert_ok(bf_response_new_from_dynbuf(&response, &dynbuf));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), 0);
    assert_int_equal(bf_response_data_len(response), data_len);
    assert_string_equal(bf_response_data(response), data);

    // dynbuf should now be empty after taking ownership
    assert_null(dynbuf.data);
}

static void new_from_dynbuf_invalid(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    char small_data[4] = {0};

    (void)state;

    // Too small dynbuf (less than sizeof(bf_response))
    assert_ok(bf_dynbuf_write(&dynbuf, small_data, sizeof(small_data)));
    assert_err(bf_response_new_from_dynbuf(&response, &dynbuf));
}

static void new_from_pack(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const char *data = "packed data";

    (void)state;

    // Create and populate a pack
    assert_ok(bf_wpack_new(&pack));
    bf_wpack_kv_str(pack, "message", data);

    assert_true(bf_wpack_is_valid(pack));
    assert_ok(bf_response_new_from_pack(&response, pack));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), 0);
    assert_int_gt(bf_response_data_len(response), 0);
}

static void new_failure(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;

    (void)state;

    assert_ok(bf_response_new_failure(&response, -EINVAL));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), -EINVAL);
    assert_int_equal(bf_response_data_len(response), 0);

    bf_response_free(&response);
    assert_null(response);

    assert_ok(bf_response_new_failure(&response, -ENOMEM));
    assert_non_null(response);
    assert_int_equal(bf_response_status(response), -ENOMEM);
}

static void copy(void **state)
{
    _free_bf_response_ struct bf_response *src = NULL;
    _free_bf_response_ struct bf_response *dest = NULL;
    const char *data = "copy test data";
    size_t data_len = strlen(data) + 1;

    (void)state;

    // Copy success response
    assert_ok(bf_response_new_success(&src, data, data_len));
    assert_ok(bf_response_copy(&dest, src));

    assert_non_null(dest);
    assert_int_equal(bf_response_status(dest), bf_response_status(src));
    assert_int_equal(bf_response_data_len(dest), bf_response_data_len(src));
    assert_int_equal(bf_response_size(dest), bf_response_size(src));
    assert_string_equal(bf_response_data(dest), bf_response_data(src));

    // Ensure it's a deep copy (different memory)
    assert_ptr_not_equal(dest, src);
    assert_ptr_not_equal(bf_response_data(dest), bf_response_data(src));

    bf_response_free(&src);
    bf_response_free(&dest);

    // Copy failure response
    assert_ok(bf_response_new_failure(&src, -EPERM));
    assert_ok(bf_response_copy(&dest, src));

    assert_non_null(dest);
    assert_int_equal(bf_response_status(dest), -EPERM);
    assert_int_equal(bf_response_data_len(dest), 0);
}

static void accessors(void **state)
{
    _free_bf_response_ struct bf_response *response = NULL;
    const char *data = "accessor test";
    size_t data_len = strlen(data) + 1;
    size_t expected_size;

    (void)state;

    assert_ok(bf_response_new_success(&response, data, data_len));

    // Test bf_response_status
    assert_int_equal(bf_response_status(response), 0);

    // Test bf_response_data
    assert_non_null(bf_response_data(response));
    assert_string_equal(bf_response_data(response), data);

    // Test bf_response_data_len
    assert_int_equal(bf_response_data_len(response), data_len);

    // Test bf_response_size (should be struct size + data_len)
    expected_size = bf_response_size(response);
    assert_int_gt(expected_size, data_len);
}

static void size_calculation(void **state)
{
    _free_bf_response_ struct bf_response *response1 = NULL;
    _free_bf_response_ struct bf_response *response2 = NULL;
    const char *small_data = "x";
    const char *large_data = "this is a much larger piece of data for testing";

    (void)state;

    assert_ok(bf_response_new_success(&response1, small_data, strlen(small_data) + 1));
    assert_ok(bf_response_new_success(&response2, large_data, strlen(large_data) + 1));

    // Larger data should result in larger size
    assert_int_gt(bf_response_size(response2), bf_response_size(response1));

    // Size difference should match data length difference
    size_t size_diff = bf_response_size(response2) - bf_response_size(response1);
    size_t data_diff = bf_response_data_len(response2) - bf_response_data_len(response1);
    assert_int_equal(size_diff, data_diff);
}

static void free_null(void **state)
{
    struct bf_response *response = NULL;

    (void)state;

    // Freeing NULL pointer should not crash
    bf_response_free(&response);
    assert_null(response);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(new_raw),
        cmocka_unit_test(new_success),
        cmocka_unit_test(new_from_dynbuf),
        cmocka_unit_test(new_from_dynbuf_invalid),
        cmocka_unit_test(new_from_pack),
        cmocka_unit_test(new_failure),
        cmocka_unit_test(copy),
        cmocka_unit_test(accessors),
        cmocka_unit_test(size_calculation),
        cmocka_unit_test(free_null),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
