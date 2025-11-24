// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

#include "mock.h"

int setns(int fd, int nstype)
{
    static int (*real)(int, int) = NULL;

    if (bft_mock_setns_is_enabled()) {
        // Return success
        return 0;
    }

    if (!real) {
        real = dlsym(RTLD_NEXT, "setns");
        if (!real) {
            (void)fprintf(stderr,
                          "failed to locate real function for setns\n");
            exit(1);
        }
    }

    return real(fd, nstype);
}
