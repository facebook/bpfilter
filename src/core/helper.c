/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/helper.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/logger.h"

#define OPEN_MODE_644 (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

void closep(int *fd)
{
    if (*fd == -1)
        return;

    if (close(*fd))
        bf_warn_r(errno, "failed to close fd %d, assuming file is closed", *fd);

    *fd = -1;
}

int bf_strncpy(char *dst, size_t len, const char *src)
{
    size_t src_len;
    size_t copy_len;

    bf_assert(dst && src);
    bf_assert(len);

    src_len = strlen(src);
    copy_len = bf_min(src_len, len - 1);

    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';

    return copy_len != src_len ? -E2BIG : 0;
}

int bf_realloc(void **ptr, size_t size)
{
    _cleanup_free_ void *_ptr;

    bf_assert(ptr);

    _ptr = realloc(*ptr, size);
    if (!_ptr)
        return -ENOMEM;

    *ptr = TAKE_PTR(_ptr);

    return 0;
}

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
        return bf_err_r(errno, "failed to open %s", path);

    _len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    _buf = malloc(_len);
    if (!_buf)
        return bf_err_r(errno, "failed to allocate memory");

    r = read(fd, _buf, _len);
    if (r < 0)
        return bf_err_r(errno, "failed to read serialized data");
    if ((size_t)r != _len)
        return bf_err_r(EIO, "can't read full serialized data");

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

    fd = open(path, O_TRUNC | O_CREAT | O_WRONLY, OPEN_MODE_644);
    if (fd < 0)
        return bf_err_r(errno, "failed to open %s", path);

    r = write(fd, buf, len);
    if (r < 0)
        return bf_err_r(errno, "failed to write to %s", path);
    if ((size_t)r != len)
        return bf_err_r(EIO, "can't write full data to %s", path);

    closep(&fd);

    return 0;
}

char *bf_ltrim(char *str)
{
    bf_assert(str);

    while (isspace(*str))
        str++;
    return str;
}

char *bf_rtrim(char *str)
{
    bf_assert(str);

    char *back = str + strlen(str);
    do {
        --back;
    } while (back > str && isspace(*back));

    *(back + 1) = '\0';
    return str;
}

char *bf_trim(char *str)
{
    bf_assert(str);

    return bf_rtrim(bf_ltrim(str));
}
