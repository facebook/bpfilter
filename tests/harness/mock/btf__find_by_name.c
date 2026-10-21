/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE
#include <bpf/btf.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "mock.h"

int btf__find_by_name(const struct btf *btf, const char *name)
{
    static int (*real)(const struct btf *, const char *) = NULL;

    if (bft_mock_btf__find_by_name_is_enabled()) {
        errno = ENOENT;
        return -ENOENT;
    }

    if (!real) {
        real = dlsym(RTLD_NEXT, "btf__find_by_name");
        if (!real) {
            (void)fprintf(
                stderr,
                "failed to locate real function for btf__find_by_name\n");
            exit(1);
        }
    }

    return real(btf, name);
}
