/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/list.h"
#include "harness/elf.h"

#define _cleanup_bf_test_ __attribute__((cleanup(bf_test_free)))
#define _cleanup_bf_test_group_ __attribute__((cleanup(bf_test_group_free)))
#define _cleanup_bf_test_suite_ __attribute__((cleanup(bf_test_suite_free)))

struct CMUnitTest;

typedef void (*bf_test_func)(void **state);

/**
 * @brief bpfilter test
 */
typedef struct
{
    /// Name of the test
    const char *name;
    /// CMocka test function
    bf_test_func fn;
} bf_test;

/**
 * @brief bpfilter test group
 *
 * A test group contains one or more tests.
 */
typedef struct
{
    const char *name;
    bf_list tests;
    struct CMUnitTest *cmtests;
} bf_test_group;

/**
 * @brief bpfilter test suite
 *
 * A test suite contains one or more test groups.
 */
typedef struct
{
    bf_list groups;
} bf_test_suite;

int bf_test_new(bf_test **test, const char *name, bf_test_func func);
void bf_test_free(bf_test **test);

int bf_test_group_new(bf_test_group **group, const char *name);
void bf_test_group_free(bf_test_group **group);
int bf_test_group_add_test(bf_test_group *group, const char *test_name,
                           bf_test_func func);
bf_test *bf_test_group_get_test(bf_test_group *group, const char *test_name);
int bf_test_group_make_cmtests(bf_test_group *group);

int bf_test_suite_new(bf_test_suite **suite);
void bf_test_suite_free(bf_test_suite **suite);
int bf_test_suite_add_test(bf_test_suite *suite, const char *group_name,
                           const char *test_name, bf_test_func func);
int bf_test_suite_add_symbol(bf_test_suite *suite, struct bf_elf_sym *sym);
bf_test_group *bf_test_suite_get_group(bf_test_suite *suite,
                                       const char *group_name);
int bf_test_suite_make_cmtests(const bf_test_suite *suite);
void bf_test_suite_dump(const bf_test_suite *suite);
