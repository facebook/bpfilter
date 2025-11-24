// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/bpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "mock.h"

#if defined(__i386__)
#define _BF_NR_bpf 357
#elif defined(__x86_64__)
#define _BF_NR_bpf 321
#elif defined(__aarch64__)
#define _BF_NR_bpf 280
#else
#error _BF_NR_bpf not defined. bpfilter does not support your arch.
#endif

// Return value for mocked BPF syscall
static atomic_long _bft_mock_syscall_retval = 0;

void bft_mock_syscall_set_retval(long retval)
{
    atomic_store(&_bft_mock_syscall_retval, retval);
}

long bft_mock_syscall_get_retval(void)
{
    return atomic_load(&_bft_mock_syscall_retval);
}

static long _bft_mock_syscall_impl(long number, ...)
{
    static long (*real)(long, ...) = NULL;
    va_list args;
    long ret;

    if (number == _BF_NR_bpf && bft_mock_syscall_is_enabled()) {
        long retval = bft_mock_syscall_get_retval();
        if (retval < 0) {
            errno = (int)(-retval);
            return -1;
        }
        return retval;
    }

    if (!real) {
        real = dlsym(RTLD_NEXT, "syscall");
        if (!real) {
            (void)fprintf(stderr,
                          "failed to locate real function for syscall\n");
            exit(1);
        }
    }

    va_start(args, number);
    // We need to extract the arguments to pass to the real syscall
    // For BPF syscall: syscall(number, cmd, attr, size)
    if (number == _BF_NR_bpf) {
        int cmd = va_arg(args, int);
        union bpf_attr *attr = va_arg(args, union bpf_attr *);
        unsigned int size = va_arg(args, unsigned int);
        va_end(args);
        ret = real(number, cmd, attr, size);
    } else {
        // For other syscalls, pass up to 6 arguments (max for syscall)
        long a1 = va_arg(args, long);
        long a2 = va_arg(args, long);
        long a3 = va_arg(args, long);
        long a4 = va_arg(args, long);
        long a5 = va_arg(args, long);
        long a6 = va_arg(args, long);
        va_end(args);
        ret = real(number, a1, a2, a3, a4, a5, a6);
    }

    return ret;
}

// Create versioned symbols to intercept glibc's syscall
long syscall(long number, ...);

#if defined(__aarch64__)
__asm__(".symver _bft_mock_syscall_impl,syscall@GLIBC_2.17");
#elif defined(__x86_64__)
__asm__(".symver _bft_mock_syscall_impl,syscall@GLIBC_2.2.5");
#elif defined(__i386__)
__asm__(".symver _bft_mock_syscall_impl,syscall@GLIBC_2.0");
#endif

// Also provide the default symbol for direct calls
long syscall(long number, ...)
{
    va_list args;
    va_start(args, number);

    // Forward to implementation
    long a1 = va_arg(args, long);
    long a2 = va_arg(args, long);
    long a3 = va_arg(args, long);
    long a4 = va_arg(args, long);
    long a5 = va_arg(args, long);
    long a6 = va_arg(args, long);
    va_end(args);

    return _bft_mock_syscall_impl(number, a1, a2, a3, a4, a5, a6);
}
