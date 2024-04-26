/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "harness/mock.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "harness/cmocka.h"

#define bf_mock_real(mock) __real_##mock
#define bf_mock_define(ret, x, args)                                           \
    bool __bf_mock_##x##_on = false;                                           \
                                                                               \
    void bf_mock_##x##_enable(void)                                            \
    {                                                                          \
        __bf_mock_##x##_on = true;                                             \
    }                                                                          \
                                                                               \
    void bf_mock_##x##_disable(void)                                           \
    {                                                                          \
        __bf_mock_##x##_on = false;                                            \
    }                                                                          \
                                                                               \
    bool bf_mock_##x##_is_enabled(void)                                        \
    {                                                                          \
        return __bf_mock_##x##_on;                                             \
    }                                                                          \
                                                                               \
    extern ret __real_##x args;                                                \
    ret __wrap_##x args

void bf_mock_cleanup(bf_mock *mock)
{
    mock->disable();
}

bf_mock_define(void *, malloc, (size_t size))
{
    if (!bf_mock_malloc_is_enabled())
        return bf_mock_real(malloc)(size);

    errno = -ENOMEM;
    return mock_type(void *);
}

bf_mock_define(void *, calloc, (size_t nmemb, size_t size))
{
    if (!bf_mock_calloc_is_enabled())
        return bf_mock_real(calloc)(nmemb, size);

    errno = -ENOMEM;
    return mock_type(void *);
}

bf_mock_define(int, open, (const char *pathname, int flags, mode_t mode))
{
    if (!bf_mock_open_is_enabled())
        return bf_mock_real(open)(pathname, flags, mode);

    errno = -ENOMEM;
    return mock_type(int);
}

bf_mock_define(ssize_t, read, (int fd, void *buf, size_t count))
{
    if (!bf_mock_read_is_enabled())
        return bf_mock_real(read)(fd, buf, count);

    errno = -ENOENT;
    return mock_type(ssize_t);
}

bf_mock_define(ssize_t, write, (int fd, const void *buf, size_t count))
{
    if (!bf_mock_write_is_enabled())
        return bf_mock_real(write)(fd, buf, count);

    errno = -ENOENT;
    return mock_type(ssize_t);
}

bf_mock_define(struct btf *, btf__load_vmlinux_btf, (void))
{
    if (!bf_mock_btf__load_vmlinux_btf_is_enabled())
        return bf_mock_real(btf__load_vmlinux_btf)();

    errno = -EINVAL;
    return mock_type(struct btf *);
}

bf_mock_define(struct nl_msg *, nlmsg_alloc, ())
{
    if (!bf_mock_nlmsg_alloc_is_enabled())
        return bf_mock_real(nlmsg_alloc)();

    errno = -EINVAL;
    return mock_type(struct nl_msg *);
}

bf_mock_define(struct nl_msg *, nlmsg_convert, (struct nlmsghdr * hdr))
{
    if (!bf_mock_nlmsg_convert_is_enabled())
        return bf_mock_real(nlmsg_convert)(hdr);

    errno = -EINVAL;
    return mock_type(struct nl_msg *);
}

bf_mock_define(struct nlmsghdr *, nlmsg_put,
               (struct nl_msg * n, uint32_t pid, uint32_t seq, int type,
                int payload, int flags))
{
    if (!bf_mock_nlmsg_put_is_enabled())
        return bf_mock_real(nlmsg_put)(n, pid, seq, type, payload, flags);

    errno = -EINVAL;
    return mock_type(struct nlmsghdr *);
}

bf_mock_define(int, nlmsg_append,
               (struct nl_msg * n, void *data, size_t len, int pad))
{
    if (!bf_mock_nlmsg_append_is_enabled())
        return bf_mock_real(nlmsg_append)(n, data, len, pad);

    errno = -EINVAL;
    return mock_type(int);
}
