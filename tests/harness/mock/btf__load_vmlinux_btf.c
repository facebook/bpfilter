#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#define _GNU_SOURCE
#include <dlfcn.h>

#include "mock.h"

struct btf;

struct btf *btf__load_vmlinux_btf(void)
{
    static struct btf *(*real)(void) = NULL;

    if (bft_mock_btf__load_vmlinux_btf_is_enabled()) {
        errno = EPERM;
        return NULL;
    }

    if (!real) {
        real = dlsym(RTLD_NEXT, "btf__load_vmlinux_btf");
        if (!real) {
            (void)fprintf(
                stderr,
                "failed to locate real function for btf__load_vmlinux_btf");
            exit(1);
        }
    }

    return real();
}
