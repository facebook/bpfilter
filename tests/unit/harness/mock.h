/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "harness/cmocka.h"

#define _cleanup_bf_mock_ __attribute__((cleanup(bf_mock_cleanup)))

#define bf_mock_declare(ret, x, args)                                          \
    void bf_mock_##x##_enable(void);                                           \
    void bf_mock_##x##_disable(void);                                          \
    bool bf_mock_##x##_is_enabled(void);                                       \
    ret __wrap_##x args;

#define bf_mock_get(name, retval)                                              \
    ({                                                                         \
        bf_mock_##name##_enable();                                             \
        will_return(__wrap_##name, retval);                                    \
        (bf_mock) {.disable = bf_mock_##name##_disable};                       \
    })

typedef struct
{
    void (*disable)(void);
} bf_mock;

void bf_mock_cleanup(bf_mock *mock);

bf_mock_declare(void *, malloc, (size_t size));
bf_mock_declare(void *, calloc, (size_t nmemb, size_t size));
bf_mock_declare(int, open, (const char *pathname, int flags, mode_t mode));
bf_mock_declare(ssize_t, read, (int fd, void *buf, size_t count));
bf_mock_declare(ssize_t, write, (int fd, const void *buf, size_t count));
