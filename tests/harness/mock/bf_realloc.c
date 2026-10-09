/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "mock.h"

int bf_realloc(void **ptr, size_t size)
{
    static int (*real)(void **, size_t) = NULL;

    if (bft_mock_bf_realloc_is_enabled())
        return -ENOMEM;

    if (!real) {
        real = dlsym(RTLD_NEXT, "bf_realloc");
        if (!real) {
            (void)fprintf(stderr,
                          "failed to locate real function for bf_realloc\n");
            exit(1);
        }
    }

    return real(ptr, size);
}
