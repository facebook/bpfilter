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
 * A mock replaces a function while it is enabled, so a test can control how
 * this function behaves.
 *
 * Keep mocks simple: only mock a function to simulate the environment (e.g. a
 * system call that requires privileges or modifies the system), or to trigger
 * a failure that a test can't cause otherwise, such as an allocation failure.
 * Don't use mocks to reach code paths that a test can reach with real inputs.
 *
 * # Technicalities
 *
 * Mocks are defined in the `mock` shared library. ctest runs the unit tests
 * with this library in `LD_PRELOAD`, so the dynamic linker resolves calls to a
 * mocked function to its mock. Run the unit tests through ctest: without the
 * preload, the real functions may be called instead. In debug builds, ASan is
 * preloaded first, so the functions it intercepts, such as `malloc()`, can't
 * be mocked.
 *
 * To add a mock:
 * 1. Implement it in its own file in `harness/mock/` (e.g.
 *    `harness/mock/bf_realloc.c`), and add the file to the `mock` library in
 *    `harness/CMakeLists.txt`. When the mock is disabled, it must call the
 *    real function, found with `dlsym(RTLD_NEXT, ...)`.
 * 2. Declare it with `bft_mock_declare()` in `harness/mock.h`, and define it
 *    with `bft_mock_define()` in `harness/mock.c`.
 * 3. In tests, enable it with `bft_mock_get()`, and use `_clean_bft_mock_` to
 *    disable it when leaving the scope.
 *
 * For example, to check that `bf_wpack_get_data()` fails when `bf_realloc()`
 * fails:
 * @code{.c}
 * {
 *     _clean_bft_mock_ bft_mock _ = bft_mock_get(bf_realloc);
 *
 *     assert_err(bf_wpack_get_data(pack, &data, &data_len));
 * }
 * @endcode
 *
 * `bft_mock_syscall_set_retval()` defines the value that the `syscall` mock
 * returns for the `bpf()` system call.
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

bft_mock_declare(bf_realloc);
bft_mock_declare(btf__load_vmlinux_btf);
bft_mock_declare(isatty);
bft_mock_declare(setns);
bft_mock_declare(syscall);

// Syscall mock helpers
void bft_mock_syscall_set_retval(long retval);
long bft_mock_syscall_get_retval(void);
