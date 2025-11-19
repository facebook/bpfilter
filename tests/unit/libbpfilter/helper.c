/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/helper.h>

#include "fake.h"
#include "test.h"

static void close_fd(void **state)
{
    int fd;

    (void)state;

    fd = 1;
    closep(&fd);
    assert_fd_empty(fd);

    closep(&fd);
    assert_fd_empty(fd);
}

static void string_copy(void **state)
{
    char lhs[64];
    char rhs[64] = "Hello";

    (void)state;

    assert_ok(bf_strncpy(lhs, 64, rhs));
    assert_string_equal(lhs, rhs);

    assert_ok(bf_strncpy(lhs, 2, "H"));
    assert_string_equal(lhs, "H");

    assert_ok(bf_strncpy(lhs, 1, ""));
    assert_string_equal(lhs, "");

    // Can't copy the whole string (including \0), so error out
    assert_err(bf_strncpy(lhs, 1, rhs));
    assert_err(bf_strncpy(lhs, strlen(rhs), rhs));
}

static void realloc_mem(void **state)
{
    _cleanup_free_ uint32_t *mem0 = NULL;
    _cleanup_free_ uint32_t *mem1 = NULL;
    (void)state;

    assert_non_null(mem0 = malloc(sizeof(*mem0)));
    *mem0 = 0xdeadbeef;

    assert_ok(bf_realloc((void **)&mem0, sizeof(mem0)));
    assert_int_equal(*mem0, 0xdeadbeef);

    assert_ok(bf_realloc((void **)&mem0, 2 * sizeof(mem0)));
    assert_int_equal(*mem0, 0xdeadbeef);

    assert_ok(bf_realloc((void **)&mem1, sizeof(*mem1)));
}

static void trim_left(void **state)
{
    char str[64];
    char *result;

    (void)state;

    // No leading whitespace
    bf_strncpy(str, sizeof(str), "Hello");
    result = bf_ltrim(str);
    assert_string_equal(result, "Hello");

    // Leading spaces
    bf_strncpy(str, sizeof(str), "   Hello");
    result = bf_ltrim(str);
    assert_string_equal(result, "Hello");

    // Leading tabs
    bf_strncpy(str, sizeof(str), "\t\tHello");
    result = bf_ltrim(str);
    assert_string_equal(result, "Hello");

    // Mixed leading whitespace
    bf_strncpy(str, sizeof(str), " \t \tHello");
    result = bf_ltrim(str);
    assert_string_equal(result, "Hello");

    // Leading and trailing whitespace (only leading trimmed)
    bf_strncpy(str, sizeof(str), "  Hello  ");
    result = bf_ltrim(str);
    assert_string_equal(result, "Hello  ");

    // Only whitespace
    bf_strncpy(str, sizeof(str), "   \t  ");
    result = bf_ltrim(str);
    assert_string_equal(result, "");

    // Empty string
    bf_strncpy(str, sizeof(str), "");
    result = bf_ltrim(str);
    assert_string_equal(result, "");

    // Newlines and other whitespace
    bf_strncpy(str, sizeof(str), "\n\r\t  Hello");
    result = bf_ltrim(str);
    assert_string_equal(result, "Hello");
}

static void trim_right(void **state)
{
    char str[64];
    char *result;

    (void)state;

    // No trailing whitespace
    bf_strncpy(str, sizeof(str), "Hello");
    result = bf_rtrim(str);
    assert_string_equal(result, "Hello");

    // Trailing spaces
    bf_strncpy(str, sizeof(str), "Hello   ");
    result = bf_rtrim(str);
    assert_string_equal(result, "Hello");

    // Trailing tabs
    bf_strncpy(str, sizeof(str), "Hello\t\t");
    result = bf_rtrim(str);
    assert_string_equal(result, "Hello");

    // Mixed trailing whitespace
    bf_strncpy(str, sizeof(str), "Hello \t \t");
    result = bf_rtrim(str);
    assert_string_equal(result, "Hello");

    // Leading and trailing whitespace (only trailing trimmed)
    bf_strncpy(str, sizeof(str), "  Hello  ");
    result = bf_rtrim(str);
    assert_string_equal(result, "  Hello");

    // Only whitespace
    bf_strncpy(str, sizeof(str), "   \t  ");
    result = bf_rtrim(str);
    assert_string_equal(result, "");

    // Empty string
    bf_strncpy(str, sizeof(str), "");
    result = bf_rtrim(str);
    assert_string_equal(result, "");

    // Newlines and other whitespace
    bf_strncpy(str, sizeof(str), "Hello  \t\r\n");
    result = bf_rtrim(str);
    assert_string_equal(result, "Hello");

    // String with internal whitespace
    bf_strncpy(str, sizeof(str), "Hello World  ");
    result = bf_rtrim(str);
    assert_string_equal(result, "Hello World");
}

static void trim_both(void **state)
{
    char str[64];
    char *result;

    (void)state;

    // No whitespace
    bf_strncpy(str, sizeof(str), "Hello");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // Leading and trailing spaces
    bf_strncpy(str, sizeof(str), "   Hello   ");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // Leading and trailing tabs
    bf_strncpy(str, sizeof(str), "\t\tHello\t\t");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // Mixed leading and trailing whitespace
    bf_strncpy(str, sizeof(str), " \t Hello \t ");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // Only leading whitespace
    bf_strncpy(str, sizeof(str), "  Hello");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // Only trailing whitespace
    bf_strncpy(str, sizeof(str), "Hello  ");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // Only whitespace
    bf_strncpy(str, sizeof(str), "   \t  ");
    result = bf_trim(str);
    assert_string_equal(result, "");

    // Empty string
    bf_strncpy(str, sizeof(str), "");
    result = bf_trim(str);
    assert_string_equal(result, "");

    // Complex whitespace with newlines
    bf_strncpy(str, sizeof(str), "\n\r\t  Hello  \t\r\n");
    result = bf_trim(str);
    assert_string_equal(result, "Hello");

    // String with internal whitespace
    bf_strncpy(str, sizeof(str), "  Hello World  ");
    result = bf_trim(str);
    assert_string_equal(result, "Hello World");

    // Multiple words with mixed whitespace
    bf_strncpy(str, sizeof(str), "\t  Hello   World  \t");
    result = bf_trim(str);
    assert_string_equal(result, "Hello   World");
}

static void write_and_read_file(void **state)
{
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    _cleanup_free_ void *read_buf = NULL;
    size_t read_len = 0;

    // Test writing and reading a simple string
    const char *test_data = "Hello, World!";
    size_t test_len = strlen(test_data);

    (void)snprintf(filepath, sizeof(filepath), "%s/test.txt", tmpdir->dir_path);

    // Write data to file
    assert_ok(bf_write_file(filepath, test_data, test_len));

    // Read data back
    assert_ok(bf_read_file(filepath, &read_buf, &read_len));
    assert_int_equal(read_len, test_len);
    assert_memory_equal(read_buf, test_data, test_len);
}

static void write_and_read_empty_file(void **state)
{
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    _cleanup_free_ void *read_buf = NULL;
    size_t read_len = 0;

    (void)snprintf(filepath, sizeof(filepath), "%s/empty.txt",
                   tmpdir->dir_path);

    // Write empty file
    assert_ok(bf_write_file(filepath, "", 0));

    // Read empty file back
    assert_ok(bf_read_file(filepath, &read_buf, &read_len));
    assert_int_equal(read_len, 0);
}

static void write_and_read_binary_data(void **state)
{
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    _cleanup_free_ void *read_buf = NULL;
    size_t read_len = 0;

    // Test binary data with null bytes
    const unsigned char test_data[] = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD,
                                       0x00, 0x42, 0xDE, 0xAD, 0xBE, 0xEF};
    size_t test_len = sizeof(test_data);

    (void)snprintf(filepath, sizeof(filepath), "%s/binary.dat",
                   tmpdir->dir_path);

    // Write binary data
    assert_ok(bf_write_file(filepath, test_data, test_len));

    // Read binary data back
    assert_ok(bf_read_file(filepath, &read_buf, &read_len));
    assert_int_equal(read_len, test_len);
    assert_memory_equal(read_buf, test_data, test_len);
}

static void write_and_read_large_file(void **state)
{
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    _cleanup_free_ void *read_buf = NULL;
    _cleanup_free_ char *test_data = NULL;
    size_t read_len = 0;
    size_t test_len = (size_t)1024 * 64; // 64 KB

    (void)snprintf(filepath, sizeof(filepath), "%s/large.dat",
                   tmpdir->dir_path);

    // Create large buffer with pattern
    test_data = malloc(test_len);
    assert_non_null(test_data);
    for (size_t i = 0; i < test_len; i++) {
        test_data[i] = (char)(i % 256);
    }

    // Write large file
    assert_ok(bf_write_file(filepath, test_data, test_len));

    // Read large file back
    assert_ok(bf_read_file(filepath, &read_buf, &read_len));
    assert_int_equal(read_len, test_len);
    assert_memory_equal(read_buf, test_data, test_len);
}

static void read_nonexistent_file(void **state)
{
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    _cleanup_free_ void *read_buf = NULL;
    size_t read_len = 0;

    (void)snprintf(filepath, sizeof(filepath), "%s/nonexistent.txt",
                   tmpdir->dir_path);

    // Reading non-existent file should fail
    assert_err(bf_read_file(filepath, &read_buf, &read_len));
}

static void overwrite_existing_file(void **state)
{
    struct bft_tmpdir *tmpdir = *(struct bft_tmpdir **)state;
    char filepath[1024];
    _cleanup_free_ void *read_buf = NULL;
    size_t read_len = 0;

    const char *first_data = "First write";
    const char *second_data = "Second write - longer than first";

    (void)snprintf(filepath, sizeof(filepath), "%s/overwrite.txt",
                   tmpdir->dir_path);

    // First write
    assert_ok(bf_write_file(filepath, first_data, strlen(first_data)));

    // Overwrite with different data
    assert_ok(bf_write_file(filepath, second_data, strlen(second_data)));

    // Read back and verify second data
    assert_ok(bf_read_file(filepath, &read_buf, &read_len));
    assert_int_equal(read_len, strlen(second_data));
    assert_memory_equal(read_buf, second_data, strlen(second_data));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(close_fd),
        cmocka_unit_test(string_copy),
        cmocka_unit_test(realloc_mem),
        cmocka_unit_test(trim_left),
        cmocka_unit_test(trim_right),
        cmocka_unit_test(trim_both),
        cmocka_unit_test_setup_teardown(write_and_read_file,
                                        btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(write_and_read_empty_file,
                                        btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(write_and_read_binary_data,
                                        btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(write_and_read_large_file,
                                        btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(read_nonexistent_file,
                                        btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
        cmocka_unit_test_setup_teardown(overwrite_existing_file,
                                        btf_setup_create_tmpdir,
                                        bft_teardown_close_tmpdir),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
