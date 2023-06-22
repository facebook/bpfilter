/* SPDX-License-Identifier: GPL-2.0 */
/*                                                                             \
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.                     \
 */

#pragma once

#include <signal.h>

#define NOT_NULL ((void *)0xdeadbeef)

#define TestAssert(suite, function, id, params)                                \
    Test(suite, function##_##id, .signal = SIGABRT)                            \
    {                                                                          \
        function params;                                                       \
    }
