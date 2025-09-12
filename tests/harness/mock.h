/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <linux/bpf.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

/**
 * @file mock.h
 *
 * Mock functions from `bpfilter` or from the standard library. Mocking function
 * allows the tester to call a stub and force the function to return a
 * predefined value. Mocks can be used to trigger a specific code path or
 * prevent a system call (which would modify the system or require elevated
 * privileges).
 *
 * Mocks must be declared in `harness/mock.h` with `bf_test_mock_declare()` and
 * implemented in `harness/mock.c` with `bf_test_mock_define()`. Then, add the
 * mocked function to `bf_test_mock()` in `harness/CMakeLists.txt`.
 *
 * In your tests, create the mock with `bf_test_mock_get(function, retval)`.
 * `retval` is the value you expect the mock to return when called. By default,
 * the mock expects to return this value only once and never be called again.
 * To configure a different behavior, use `bf_test_mock_get_empty()` and
 * `bf_test_mock_will_return()` or `bf_test_mock_will_return_always()`. Use
 * `_clean_bf_test_mock_` to limit your mock to the current scope.
 *
 * Using a mock to ensure `_bf_print_msg_new()` fails if `malloc()` fails:
 * @code{.c}
 * // Create a mock for malloc which will return NULL once.
 * _clean_bf_test_mock bf_test_mock _ bf_test_mock_get(malloc, NULL);
 *
 * // Expect the function to fail if malloc fails.
 * assert_error(_bf_printer_msg_new(&msg));
 * @endcode
 *
 * This module also defines convenience function to simulate a runtime
 * environment such as creating a temporary file to serialize the daemon into.
 */

#define _free_tmp_file_ __attribute__((cleanup(bf_test_filepath_free)))

char *bf_test_filepath_new_rw(void);
void bf_test_filepath_free(char **path);

#define _clean_bf_test_mock_ __attribute__((cleanup(bf_test_mock_clean)))

#define bf_test_mock_declare(ret, x, args)                                     \
    void bf_test_mock_##x##_enable(void);                                      \
    void bf_test_mock_##x##_disable(void);                                     \
    bool bf_test_mock_##x##_is_enabled(void);                                  \
    ret __wrap_##x args;

#define bf_test_mock_get(name, retval)                                         \
    ({                                                                         \
        bf_test_mock_##name##_enable();                                        \
        will_return(__wrap_##name, retval);                                    \
        (bf_test_mock) {.disable = bf_test_mock_##name##_disable,              \
                        .wrap_name = BF_STR(__wrap_##name)};                   \
    })

#define bf_test_mock_empty(name)                                               \
    ({                                                                         \
        bf_test_mock_##name##_enable();                                        \
        (bf_test_mock) {                                                       \
            .disable = bf_test_mock_##name##_disable,                          \
            .wrap_name = BF_STR(__wrap_##name),                                \
        };                                                                     \
    })

#define bf_test_mock_will_return(mock, value)                                  \
    _will_return((mock).wrap_name, __FILE__, __LINE__, ((uintmax_t)(value)), 1)

#define bf_test_mock_will_return_always(mock, value)                           \
    _will_return((mock).wrap_name, __FILE__, __LINE__, ((uintmax_t)(value)), -1)

#define bf_test_mock_real(mock) __real_##mock
#define bf_test_mock_define(ret, x, args)                                      \
    bool __bf_test_mock_##x##_on = false;                                      \
                                                                               \
    void bf_test_mock_##x##_enable(void)                                       \
    {                                                                          \
        __bf_test_mock_##x##_on = true;                                        \
    }                                                                          \
                                                                               \
    void bf_test_mock_##x##_disable(void)                                      \
    {                                                                          \
        __bf_test_mock_##x##_on = false;                                       \
    }                                                                          \
                                                                               \
    bool bf_test_mock_##x##_is_enabled(void)                                   \
    {                                                                          \
        return __bf_test_mock_##x##_on;                                        \
    }                                                                          \
                                                                               \
    extern ret __real_##x args;                                                \
    ret __wrap_##x args

typedef struct
{
    void (*disable)(void);
    const char *wrap_name;
} bf_test_mock;

void bf_test_mock_clean(bf_test_mock *mock);
