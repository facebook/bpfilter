/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/mock.h"

#include <linux/bpf.h>

// clang-format off
#include <setjmp.h> // NOLINT: required by CMocka
#include <cmocka.h>
// clang-format on

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/helper.h"
#include "core/logger.h"

#define bf_test_mock_real(mock) __real_##mock
#define bf_test_mock_define(ret, x, args)                                      \
    bool __bf_test_mock_##x##_on = false;                                      \
                                                                               \
    void bf_test_mock_##x##_enable(void)                                       \
    {                                                                          \
        __bf_test_mock_##x##_on = true;                                        \
    }                                                                          \
                                                                               \
    void bf_test_mock_##x##_disable(void)                                      \
    {                                                                          \
        __bf_test_mock_##x##_on = false;                                       \
    }                                                                          \
                                                                               \
    bool bf_test_mock_##x##_is_enabled(void)                                   \
    {                                                                          \
        return __bf_test_mock_##x##_on;                                        \
    }                                                                          \
                                                                               \
    extern ret __real_##x args;                                                \
    ret __wrap_##x args

static const char *_bf_readable_file_content = "Hello, world!";

char *bf_test_filepath_new_rw(void)
{
    int fd;
    size_t len = strlen(_bf_readable_file_content);
    char tmppath[] = "/tmp/bpfltr_XXXXXX";
    char *path = NULL;

    fd = mkstemp(tmppath);
    if (fd < 0) {
        bf_err_r(errno, "failed to create a temporary file path");
        return NULL;
    }

    if ((ssize_t)len != write(fd, _bf_readable_file_content, len)) {
        bf_err_r(errno, "failed to write to the temporary filepath");
        return NULL;
    }

    close(fd);

    path = strdup(tmppath);
    if (!path) {
        bf_err_r(errno, "failed to allocate memory for the new filepath");
        return NULL;
    }

    return path;
}

void bf_test_filepath_free(char **path)
{
    bf_assert(path);

    if (!*path)
        return;

    if (unlink(*path) < 0)
        bf_err_r(errno, "failed to remove '%s'", *path);

    freep((void *)path);
}

void bf_test_mock_clean(bf_test_mock *mock)
{
    mock->disable();
}

bf_test_mock_define(void *, malloc, (size_t size))
{
    if (!bf_test_mock_malloc_is_enabled())
        return bf_test_mock_real(malloc)(size);

    errno = -ENOMEM;
    return mock_type(void *);
}

bf_test_mock_define(void *, calloc, (size_t nmemb, size_t size))
{
    if (!bf_test_mock_calloc_is_enabled())
        return bf_test_mock_real(calloc)(nmemb, size);

    errno = -ENOMEM;
    return mock_type(void *);
}

bf_test_mock_define(int, open, (const char *pathname, int flags, mode_t mode))
{
    if (!bf_test_mock_open_is_enabled())
        return bf_test_mock_real(open)(pathname, flags, mode);

    errno = -ENOMEM;
    return mock_type(int);
}

bf_test_mock_define(ssize_t, read, (int fd, void *buf, size_t count))
{
    if (!bf_test_mock_read_is_enabled())
        return bf_test_mock_real(read)(fd, buf, count);

    errno = -ENOENT;
    return mock_type(ssize_t);
}

bf_test_mock_define(ssize_t, write, (int fd, const void *buf, size_t count))
{
    if (!bf_test_mock_write_is_enabled())
        return bf_test_mock_real(write)(fd, buf, count);

    errno = -ENOENT;
    return mock_type(ssize_t);
}

bf_test_mock_define(struct btf *, btf__load_vmlinux_btf, (void))
{
    if (!bf_test_mock_btf__load_vmlinux_btf_is_enabled())
        return bf_test_mock_real(btf__load_vmlinux_btf)();

    errno = -EINVAL;
    return mock_type(struct btf *);
}

bf_test_mock_define(struct nl_msg *, nlmsg_alloc, ())
{
    if (!bf_test_mock_nlmsg_alloc_is_enabled())
        return bf_test_mock_real(nlmsg_alloc)();

    errno = -EINVAL;
    return mock_type(struct nl_msg *);
}

bf_test_mock_define(struct nl_msg *, nlmsg_convert, (struct nlmsghdr * hdr))
{
    if (!bf_test_mock_nlmsg_convert_is_enabled())
        return bf_test_mock_real(nlmsg_convert)(hdr);

    errno = -EINVAL;
    return mock_type(struct nl_msg *);
}

bf_test_mock_define(struct nlmsghdr *, nlmsg_put,
                    (struct nl_msg * nlmsg, uint32_t pid, uint32_t seq,
                     int type, int payload, int flags))
{
    if (!bf_test_mock_nlmsg_put_is_enabled())
        return bf_test_mock_real(nlmsg_put)(nlmsg, pid, seq, type, payload,
                                            flags);

    errno = -EINVAL;
    return mock_type(struct nlmsghdr *);
}

bf_test_mock_define(int, nlmsg_append,
                    (struct nl_msg * nlmsg, void *data, size_t len, int pad))
{
    if (!bf_test_mock_nlmsg_append_is_enabled())
        return bf_test_mock_real(nlmsg_append)(nlmsg, data, len, pad);

    errno = -EINVAL;
    return mock_type(int);
}

bf_test_mock_define(int, bf_bpf_obj_get, (const char *path, int *fd))
{
    if (!bf_test_mock_bf_bpf_obj_get_is_enabled())
        return bf_test_mock_real(bf_bpf_obj_get)(path, fd);

    return mock_type(int);
}

bf_test_mock_define(int, vsnprintf,
                    (char *str, size_t size, const char *fmt, va_list args))
{
    if (!bf_test_mock_vsnprintf_is_enabled())
        return bf_test_mock_real(vsnprintf)(str, size, fmt, args);

    return mock_type(int);
}

bf_test_mock_define(int, snprintf,
                    (char *str, size_t size, const char *fmt, ...))
{
    if (!bf_test_mock_snprintf_is_enabled()) {
        int r;
        va_list args;

        va_start(args, fmt);
        r = bf_test_mock_real(vsnprintf)(str, size, fmt, args);
        va_end(args);

        return r;
    }

    return mock_type(int);
}

bf_test_mock_define(int, bf_bpf, (enum bpf_cmd cmd, union bpf_attr *attr))
{
    if (!bf_test_mock_bf_bpf_is_enabled())
        return bf_test_mock_real(bf_bpf)(cmd, attr);

    return mock_type(int);
}
