/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

extern void mock_assert(const int result, const char * const expression,
                        const char * const file, const int line);

#ifndef bf_assert
#define bf_assert(expression)                                                  \
    mock_assert((int)(!!(expression)), #expression, __FILE__, __LINE__)
#else
#error bf_assert is already defined, it should not
#endif
