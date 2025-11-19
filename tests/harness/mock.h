/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

// clang-format off
#include <stdarg.h> // NOLINT: required by cmocka.h
#include <stddef.h> // NOLINT: required by cmocka.h
#include <stdint.h> // NOLINT: required by cmocka.h
#include <setjmp.h> // NOLINT: required by cmocka.h
#include <cmocka.h> // NOLINT: required by cmocka.h
// clang-format on

#include <stdbool.h>

/**
 * @file mock.h
 *
 * Mock functions are used to wrap a system call or an external library function
 * in order to simplify the test of a libbpfilter function, or prevent it from
 * modifying the underlying system.
 *
 * ## Technicalities

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


MOCKING IS ONLY TO MOCK, not to trigger different code path during testing
-> KISS


 */

struct btf;

#include <stdio.h>

#include <bpfilter/helper.h>

#define _clean_bft_mock_ __attribute__((cleanup(bft_mock_clean)))

#define bft_mock_declare(fn)                                                   \
    void bft_mock_##fn##_enable(void);                                         \
    void bft_mock_##fn##_disable(void);                                        \
    bool bft_mock_##fn##_is_enabled(void);

#define bft_mock_get(name)                                                     \
    ({                                                                         \
        bft_mock_##name##_enable();                                            \
        (bft_mock) {.disable = bft_mock_##name##_disable,                      \
                    .wrap_name = BF_STR(__wrap_##name)};                       \
    })

#define bft_mock_real(mock) __real_##mock
#define bft_mock_define(x)                                                     \
    static bool _bft_mock_##x##_on = false;                                    \
                                                                               \
    void bft_mock_##x##_enable(void)                                           \
    {                                                                          \
        _bft_mock_##x##_on = true;                                             \
    }                                                                          \
                                                                               \
    void bft_mock_##x##_disable(void)                                          \
    {                                                                          \
        _bft_mock_##x##_on = false;                                            \
    }                                                                          \
                                                                               \
    bool bft_mock_##x##_is_enabled(void)                                       \
    {                                                                          \
        return _bft_mock_##x##_on;                                             \
    }

typedef struct
{
    void (*disable)(void);
    const char *wrap_name;
} bft_mock;

void bft_mock_clean(bft_mock *mock);

bft_mock_declare(btf__load_vmlinux_btf);
bft_mock_declare(isatty);
bft_mock_declare(setns);
bft_mock_declare(syscall);

// Syscall mock helpers
void bft_mock_syscall_set_retval(long retval);
long bft_mock_syscall_get_retval(void);
