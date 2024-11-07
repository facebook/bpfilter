/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

/**
 * @file test.h
 *
 * Main file to include to perform tests. This header defines convenience macros
 * to create tests and test results.
 */

#pragma once

// clang-format off
#include <stdarg.h> // NOLINT: required by cmocka.h
#include <stddef.h> // NOLINT: required by cmocka.h
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h>
// clang-format on

#include <stdbool.h>
#include <stdint.h>

#include "core/dump.h"
#include "core/helper.h"
#include "core/list.h"
#include "harness/sym.h"

struct CMUnitTest;

/**
 * Macro to use when checking if `NULL` parameters are properly asserted on:
 *
 * @code{.c}
 * // Ensure path can't be NULL
 * expect_assert_failure(bf_read_file(NULL, NOT_NULL, 0));
 * // Ensure buf can't be NULL
 * expect_assert_failure(bf_read_file(NOT_NULL, NULL, 0));
 * @endcode
 */
#define NOT_NULL ((void *)0xdeadbeef)

/**
 * Create a new test.
 *
 * Tests are defined in their section so they can be easily discovered at
 * runtime time.
 *
 * @param group Test group, can be filtered on to run all the tests in a single
 *        group.
 * @param name Name of the test.
 */
#define Test(group, name)                                                      \
    __attribute__((section(".bf_test"))) void group##__##name(                 \
        bf_unused void **state)

/**
 * Assert that @p x evaluates to a success.
 *
 * @param x Expression to evaluate. If the expression evaluates to `0`, it is
 *          considered succeeded, and the assertion succeeds.
 */
#define assert_success(x) assert_int_equal(0, (x))

/**
 * Assert that @p x evaluates to an error.
 *
 * @param x Expression to evaluate. If the expression evaluates to `< 0`, it is
 *          considered failed, and the assertion succeeds.
 */
#define assert_error(x) assert_int_not_equal(0, (x))

#define _free_bf_test_ __attribute__((cleanup(bf_test_free)))
#define _free_bf_test_group_ __attribute__((cleanup(bf_test_group_free)))
#define _free_bf_test_suite_ __attribute__((cleanup(bf_test_suite_free)))

typedef void (*bf_test_cb)(void **state);

/**
 * Test
 */
typedef struct
{
    /// Name of the test.
    const char *name;
    /// Test function.
    bf_test_cb cb;
} bf_test;

int bf_test_new(bf_test **test, const char *name, bf_test_cb cb);
void bf_test_free(bf_test **test);
void bf_test_dump(const bf_test *test, prefix_t *prefix);

/**
 * Test group.
 *
 * A test group contains one or more tests.
 */
typedef struct
{
    /// Name of the test group.
    const char *name;
    /// List of tests in the group.
    bf_list tests;
    /// CMocka test object, for CMocka's primitives to run the tests.
    struct CMUnitTest *cmtests;
} bf_test_group;

int bf_test_group_new(bf_test_group **group, const char *name);
void bf_test_group_free(bf_test_group **group);
void bf_test_group_dump(const bf_test_group *group, prefix_t *prefix);
int bf_test_group_add_test(bf_test_group *group, const char *test_name,
                           bf_test_cb cb);
bf_test *bf_test_group_get_test(bf_test_group *group, const char *test_name);
int bf_test_group_make_cmtests(bf_test_group *group);

/**
 * Test suite.
 *
 * A test suite contains one or more test groups.
 */
typedef struct
{
    /// List of test groups.
    bf_list groups;
} bf_test_suite;

int bf_test_suite_new(bf_test_suite **suite);
void bf_test_suite_free(bf_test_suite **suite);
void bf_test_suite_dump(const bf_test_suite *suite, prefix_t *prefix);
void bf_test_suite_print(const bf_test_suite *suite);
int bf_test_suite_add_test(bf_test_suite *suite, const char *group_name,
                           const char *test_name, bf_test_cb cb);
int bf_test_suite_add_symbol(bf_test_suite *suite, struct bf_test_sym *sym);
bf_test_group *bf_test_suite_get_group(bf_test_suite *suite,
                                       const char *group_name);
int bf_test_suite_make_cmtests(const bf_test_suite *suite);
