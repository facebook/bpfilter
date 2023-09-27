/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/helper.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core/logger.h"
#include "shared/helper.h"

int bf_read_file(const char *path, void **buf, size_t *len)
{
    _cleanup_close_ int fd = -1;
    _cleanup_free_ void *_buf = NULL;
    size_t _len;
    ssize_t r;

    bf_assert(path);
    bf_assert(buf);
    bf_assert(len);

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return bf_err_code(errno, "failed to open %s", path);

    _len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    _buf = malloc(_len);
    if (!_buf)
        return bf_err_code(errno, "failed to allocate memory");

    r = read(fd, _buf, _len);
    if (r < 0)
        return bf_err_code(errno, "failed to read serialized data");
    if ((size_t)r != _len)
        return bf_err_code(EIO, "can't read full serialized data");

    closep(&fd);

    *buf = TAKE_PTR(_buf);
    *len = _len;

    return 0;
}

int bf_write_file(const char *path, const void *buf, size_t len)
{
    _cleanup_close_ int fd = -1;
    ssize_t r;

    bf_assert(path);
    bf_assert(buf);

    fd = open(path, O_TRUNC | O_CREAT | O_WRONLY, 0644);
    if (fd < 0)
        return bf_err_code(errno, "failed to open %s", path);

    r = write(fd, buf, len);
    if (r < 0)
        return bf_err_code(errno, "failed to write to %s", path);
    if ((size_t)r != len)
        return bf_err_code(EIO, "can't write full data to %s", path);

    closep(&fd);

    return 0;
}
