/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/pack.h"

#include <errno.h>
#include <string.h>

#include "fake.h"
#include "test.h"

static void wpack_new_free(void **state)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;

    (void)state;

    assert_ok(bf_wpack_new(&pack));
    assert_non_null(pack);
    assert_true(bf_wpack_is_valid(pack));

    bf_wpack_free(&pack);
    assert_null(pack);

    // Freeing NULL should be safe
    bf_wpack_free(&pack);
}

static void wpack_primitives(void **state)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&pack));

    // Write various primitives
    bf_wpack_kv_int(pack, "int_val", -42);
    bf_wpack_kv_uint(pack, "uint_val", 42);
    bf_wpack_kv_u8(pack, "u8_val", 255);
    bf_wpack_kv_u16(pack, "u16_val", 65535);
    bf_wpack_kv_u32(pack, "u32_val", 0xDEADBEEF);
    bf_wpack_kv_u64(pack, "u64_val", 0xDEADBEEFCAFEBABE);
    bf_wpack_kv_bool(pack, "bool_val", true);
    bf_wpack_kv_str(pack, "str_val", "hello world");
    bf_wpack_kv_nil(pack, "nil_val");

    assert_true(bf_wpack_is_valid(pack));
    assert_ok(bf_wpack_get_data(pack, &data, &data_len));
    assert_non_null(data);
    assert_int_gt(data_len, 0);
}

static void wpack_binary(void **state)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const char *bin_data = "\x00\x01\x02\x03\x04";
    size_t bin_len = 5;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&pack));

    bf_wpack_kv_bin(pack, "binary", bin_data, bin_len);

    assert_true(bf_wpack_is_valid(pack));
    assert_ok(bf_wpack_get_data(pack, &data, &data_len));
    assert_non_null(data);
    assert_int_gt(data_len, 0);
}

static void wpack_nested_objects(void **state)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&pack));

    // Create nested object with key
    bf_wpack_open_object(pack, "nested");
    bf_wpack_kv_int(pack, "value", 123);
    bf_wpack_kv_str(pack, "name", "test");
    bf_wpack_close_object(pack);

    // Create another nested object with key
    bf_wpack_open_object(pack, "another");
    bf_wpack_kv_bool(pack, "flag", false);
    bf_wpack_close_object(pack);

    assert_true(bf_wpack_is_valid(pack));
    assert_ok(bf_wpack_get_data(pack, &data, &data_len));
    assert_non_null(data);
}

static void wpack_arrays(void **state)
{
    _free_bf_wpack_ bf_wpack_t *pack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    assert_ok(bf_wpack_new(&pack));

    // Create array with key
    bf_wpack_open_array(pack, "numbers");
    bf_wpack_int(pack, 1);
    bf_wpack_int(pack, 2);
    bf_wpack_int(pack, 3);
    bf_wpack_close_array(pack);

    // Create another array with key
    bf_wpack_open_array(pack, "strings");
    bf_wpack_str(pack, "a");
    bf_wpack_str(pack, "b");
    bf_wpack_close_array(pack);

    assert_true(bf_wpack_is_valid(pack));
    assert_ok(bf_wpack_get_data(pack, &data, &data_len));
    assert_non_null(data);
}

static void rpack_primitives(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;
    int int_val;
    unsigned int uint_val;
    uint8_t u8_val;
    uint16_t u16_val;
    uint32_t u32_val;
    uint64_t u64_val;
    bool bool_val;
    _cleanup_free_ char *str_val = NULL;

    (void)state;

    // Create packed data
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_int(wpack, "int_val", -42);
    bf_wpack_kv_uint(wpack, "uint_val", 42);
    bf_wpack_kv_u8(wpack, "u8_val", 255);
    bf_wpack_kv_u16(wpack, "u16_val", 65535);
    bf_wpack_kv_u32(wpack, "u32_val", 0xDEADBEEF);
    bf_wpack_kv_u64(wpack, "u64_val", 0xDEADBEEFCAFEBABE);
    bf_wpack_kv_bool(wpack, "bool_val", true);
    bf_wpack_kv_str(wpack, "str_val", "hello world");
    bf_wpack_kv_nil(wpack, "nil_val");
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    assert_ok(bf_rpack_kv_int(root, "int_val", &int_val));
    assert_int_equal(int_val, -42);

    assert_ok(bf_rpack_kv_uint(root, "uint_val", &uint_val));
    assert_int_equal(uint_val, 42);

    assert_ok(bf_rpack_kv_u8(root, "u8_val", &u8_val));
    assert_int_equal(u8_val, 255);

    assert_ok(bf_rpack_kv_u16(root, "u16_val", &u16_val));
    assert_int_equal(u16_val, 65535);

    assert_ok(bf_rpack_kv_u32(root, "u32_val", &u32_val));
    assert_int_equal(u32_val, 0xDEADBEEF);

    assert_ok(bf_rpack_kv_u64(root, "u64_val", &u64_val));
    assert_true(u64_val == 0xDEADBEEFCAFEBABE);

    assert_ok(bf_rpack_kv_bool(root, "bool_val", &bool_val));
    assert_true(bool_val);

    assert_ok(bf_rpack_kv_str(root, "str_val", &str_val));
    assert_string_equal(str_val, "hello world");

    // Test nil check
    bf_rpack_node_t nil_node;
    assert_ok(bf_rpack_kv_node(root, "nil_val", &nil_node));
    assert_true(bf_rpack_is_nil(nil_node));
}

static void rpack_binary(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *wdata;
    size_t wdata_len;
    bf_rpack_node_t root;
    const char *bin_data = "\x00\x01\x02\x03\x04";
    size_t bin_len = 5;
    const void *read_data;
    size_t read_len;

    (void)state;

    // Create packed data
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_bin(wpack, "binary", bin_data, bin_len);
    assert_ok(bf_wpack_get_data(wpack, &wdata, &wdata_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, wdata, wdata_len));
    root = bf_rpack_root(rpack);

    assert_ok(bf_rpack_kv_bin(root, "binary", &read_data, &read_len));
    assert_int_equal(read_len, bin_len);
    assert_memory_equal(read_data, bin_data, bin_len);
}

static void rpack_nested_objects(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;
    bf_rpack_node_t nested;
    int value;
    _cleanup_free_ char *name = NULL;

    (void)state;

    // Create packed data with nested object
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_object(wpack, "nested");
    bf_wpack_kv_int(wpack, "value", 123);
    bf_wpack_kv_str(wpack, "name", "test");
    bf_wpack_close_object(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    assert_ok(bf_rpack_kv_obj(root, "nested", &nested));
    assert_ok(bf_rpack_kv_int(nested, "value", &value));
    assert_int_equal(value, 123);
    assert_ok(bf_rpack_kv_str(nested, "name", &name));
    assert_string_equal(name, "test");
}

static void rpack_arrays(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;
    bf_rpack_node_t array;
    bf_rpack_node_t element;
    int value;

    (void)state;

    // Create packed data with array
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_open_array(wpack, "numbers");
    bf_wpack_int(wpack, 10);
    bf_wpack_int(wpack, 20);
    bf_wpack_int(wpack, 30);
    bf_wpack_close_array(wpack);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    assert_ok(bf_rpack_kv_array(root, "numbers", &array));
    assert_true(bf_rpack_is_array(array));
    assert_int_equal(bf_rpack_array_count(array), 3);

    element = bf_rpack_array_value_at(array, 0);
    assert_ok(bf_rpack_int(element, &value));
    assert_int_equal(value, 10);

    element = bf_rpack_array_value_at(array, 1);
    assert_ok(bf_rpack_int(element, &value));
    assert_int_equal(value, 20);

    element = bf_rpack_array_value_at(array, 2);
    assert_ok(bf_rpack_int(element, &value));
    assert_int_equal(value, 30);
}

static void rpack_contains(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;

    (void)state;

    // Create packed data
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_int(wpack, "exists", 42);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    assert_true(bf_rpack_kv_contains(root, "exists"));
    assert_false(bf_rpack_kv_contains(root, "not_exists"));
}

static void rpack_errors(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;
    int int_val;
    unsigned int uint_val;
    bool bool_val;

    (void)state;

    // Create packed data
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_int(wpack, "int_val", 42);
    bf_wpack_kv_str(wpack, "str_val", "hello");
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    // Try to read non-existent key
    assert_err(bf_rpack_kv_int(root, "missing", &int_val));

    // Try to read wrong type
    assert_err(bf_rpack_kv_uint(root, "str_val", &uint_val));
    assert_err(bf_rpack_kv_bool(root, "int_val", &bool_val));
}

static void rpack_new_free(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;

    (void)state;

    // Create some valid packed data
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_int(wpack, "test", 1);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    assert_ok(bf_rpack_new(&rpack, data, data_len));
    assert_non_null(rpack);

    bf_rpack_free(&rpack);
    assert_null(rpack);

    // Freeing NULL should be safe
    bf_rpack_free(&rpack);

    // Truncated data should fail (map with 10 elements but no data)
    char invalid[] = "\x8a"; // fixmap with 10 elements, but no data follows
    assert_err(bf_rpack_new(&rpack, invalid, sizeof(invalid) - 1));
}

static void wpack_enum(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;
    int enum_val;

    (void)state;

    // Create packed data with enum (stored as int)
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_enum(wpack, "enum_val", 5);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read it back
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    assert_ok(bf_rpack_kv_enum(root, "enum_val", &enum_val, 0, 10));
    assert_err(bf_rpack_kv_enum(root, "enum_val", &enum_val, 0, 5));
    assert_err(bf_rpack_kv_enum(root, "enum_val", &enum_val, 6, 10));
    assert_int_equal(enum_val, 5);
}

static void rpack_direct_node_access(void **state)
{
    _free_bf_wpack_ bf_wpack_t *wpack = NULL;
    _free_bf_rpack_ bf_rpack_t *rpack = NULL;
    const void *data;
    size_t data_len;
    bf_rpack_node_t root;
    bf_rpack_node_t child;
    int value;

    (void)state;

    // Create packed data
    assert_ok(bf_wpack_new(&wpack));
    bf_wpack_kv_int(wpack, "value", 999);
    assert_ok(bf_wpack_get_data(wpack, &data, &data_len));

    // Read using kv_node then direct access
    assert_ok(bf_rpack_new(&rpack, data, data_len));
    root = bf_rpack_root(rpack);

    assert_ok(bf_rpack_kv_node(root, "value", &child));
    assert_ok(bf_rpack_int(child, &value));
    assert_int_equal(value, 999);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(wpack_new_free),
        cmocka_unit_test(wpack_primitives),
        cmocka_unit_test(wpack_binary),
        cmocka_unit_test(wpack_nested_objects),
        cmocka_unit_test(wpack_arrays),
        cmocka_unit_test(wpack_enum),
        cmocka_unit_test(rpack_new_free),
        cmocka_unit_test(rpack_primitives),
        cmocka_unit_test(rpack_binary),
        cmocka_unit_test(rpack_nested_objects),
        cmocka_unit_test(rpack_arrays),
        cmocka_unit_test(rpack_contains),
        cmocka_unit_test(rpack_errors),
        cmocka_unit_test(rpack_direct_node_access),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
