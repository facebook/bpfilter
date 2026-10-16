/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "mock.h"

int getentropy(void *buffer, size_t length)
{
    static int (*real)(void *, size_t) = NULL;

    if (bft_mock_getentropy_is_enabled()) {
        errno = EIO;
        return -1;
    }

    if (!real) {
        real = dlsym(RTLD_NEXT, "getentropy");
        if (!real) {
            (void)fprintf(stderr,
                          "failed to locate real function for getentropy\n");
            exit(1);
        }
    }

    return real(buffer, length);
}
