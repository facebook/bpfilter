/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#pragma once

#include <signal.h>

#define NOT_NULL ((void *)0xdeadbeef)

/**
 * @brief Generate a test for `assert()` calls in a function.
 *
 * Requirements on a function's arguments are check by `assert()`. This macro
 * generates a test that calls the function with the given arguments and
 * expects the process to abort with `SIGABRT`.
 *
 * @param suite The test suite to add the test to.
 * @param function The function to test.
 * @param params The parameters to pass to the function. This must be a
 *  parenthesized list of arguments.
 */
#define TestAssert(suite, function, params)                                    \
    _TestAssert(suite, function, __COUNTER__, params)

#define _TestAssert(suite, function, id, params)                               \
    __TestAssert(suite, function, id, params)

#define __TestAssert(suite, function, id, params)                              \
    Test(suite, function##_##id, .signal = SIGABRT)                            \
    {                                                                          \
        function params;                                                       \
    }

/**
 * @brief Generate a manual test for `assert()` calls in a function.
 *
 * Similar to @ref TestAssert, but the test is not automatically defined.
 * Instead, the test is generated with a unique name and must be defined
 * manually. This is useful when the test needs to be customized, e.g. to
 * define a valid pointer to NULL.
 *
 * @param suite The test suite to add the test to.
 * @param function The function to test.
 */
#define TestAssertManual(suite, function)                                      \
    _TestAssertManual(suite, function, __COUNTER__)

#define _TestAssertManual(suite, function, id)                                 \
    __TestAssertManual(suite, function, id)

#define __TestAssertManual(suite, function, id)                                \
    Test(suite, function##_##id, .signal = SIGABRT)
