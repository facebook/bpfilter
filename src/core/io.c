/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/io.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/helper.h"
#include "core/logger.h"
#include "core/request.h"
#include "core/response.h"

#define BF_PERM_755 (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)

static ssize_t _bf_recv_in_buff(int fd, void *buf, size_t buf_len)
{
    ssize_t bytes_read = 0;
    ssize_t r;

    bf_assert(buf);

    do {
        /// @todo Add a timeout to the socket to prevent blocking forever.
        r = read(fd, buf + bytes_read, buf_len - bytes_read);
        if (r < 0) {
            (void)fprintf(stderr, "can't read from the socket: %s\n",
                          bf_strerror(errno));
            return -errno;
        }

        bytes_read += r;
    } while (r && (size_t)bytes_read != buf_len);

    return bytes_read;
}

static ssize_t _bf_send_from_buff(int fd, void *buf, size_t buf_len)
{
    ssize_t bytes_sent = 0;
    ssize_t r;

    bf_assert(buf);

    while ((size_t)bytes_sent < buf_len) {
        r = write(fd, buf + bytes_sent, buf_len - bytes_sent);
        if (r < 0) {
            (void)fprintf(stderr, "can't write to socket: %s\n",
                          bf_strerror(errno));
            return -errno;
        }

        bytes_sent += r;
    }

    return bytes_sent;
}

int bf_send_request(int fd, const struct bf_request *request)
{
    ssize_t r;

    bf_assert(request);

    r = _bf_send_from_buff(fd, (void *)request, bf_request_size(request));
    if (r < 0) {
        (void)fprintf(stderr, "Failed to send request: %s\n",
                      bf_strerror(errno));
        return -errno;
    }

    if ((size_t)r != bf_request_size(request)) {
        (void)fprintf(stderr,
                      "Failed to send request: %lu bytes sent, %ld expected\n",
                      (size_t)r, bf_request_size(request));
        return -EIO;
    }

    return 0;
}

int bf_recv_request(int fd, struct bf_request **request)
{
    struct bf_request req;
    _cleanup_bf_request_ struct bf_request *_request = NULL;
    ssize_t r;

    bf_assert(request);

    r = _bf_recv_in_buff(fd, &req, sizeof(req));
    if (r < 0)
        return (int)r;

    if ((size_t)r != sizeof(req)) {
        (void)fprintf(stderr,
                      "failed to read request: %lu bytes read, %lu expected\n",
                      (size_t)r, sizeof(req));
        return -EIO;
    }

    _request = malloc(bf_request_size(&req));
    if (!_request) {
        (void)fprintf(stderr, "failed to allocate request: %s\n",
                      bf_strerror(errno));
        return -errno;
    }

    memcpy(_request, &req, sizeof(req));

    r = _bf_recv_in_buff(fd, _request->data, _request->data_len);
    if (r < 0)
        return (int)r;

    if ((size_t)r != _request->data_len) {
        (void)fprintf(stderr,
                      "failed to read request: %lu bytes read, %lu expected\n",
                      (size_t)r, _request->data_len);
        return -EIO;
    }

    *request = TAKE_PTR(_request);

    return 0;
}

int bf_send_response(int fd, struct bf_response *response)
{
    ssize_t r;

    bf_assert(response);

    r = _bf_send_from_buff(fd, (void *)response, bf_response_size(response));
    if (r < 0) {
        (void)fprintf(stderr, "Failed to send response: %s\n",
                      bf_strerror(errno));
        return -errno;
    }

    if ((size_t)r != bf_response_size(response)) {
        (void)fprintf(stderr,
                      "Failed to send response: %lu bytes sent, %ld expected\n",
                      r, bf_response_size(response));
        return -EIO;
    }

    return 0;
}

int bf_recv_response(int fd, struct bf_response **response)
{
    struct bf_response res;
    _cleanup_bf_response_ struct bf_response *_response = NULL;
    ssize_t r;

    bf_assert(response);

    r = _bf_recv_in_buff(fd, &res, sizeof(res));
    if (r < 0)
        return -errno;

    if ((size_t)r != sizeof(res)) {
        (void)fprintf(stderr,
                      "failed to read response: %lu bytes read, %lu expected\n",
                      (size_t)r, sizeof(res));
        return -EIO;
    }

    _response = malloc(bf_response_size(&res));
    if (!_response) {
        (void)fprintf(stderr, "failed to allocate response: %s\n",
                      bf_strerror(errno));
        return -errno;
    }

    memcpy(_response, &res, sizeof(res));

    r = _bf_recv_in_buff(fd, _response->data, _response->data_len);
    if (r < 0)
        return (int)r;

    if (_response->type == BF_RES_SUCCESS && (size_t)r != _response->data_len) {
        (void)fprintf(stderr,
                      "failed to read response: %lu bytes read, %lu expected\n",
                      (size_t)r, _response->data_len);
        return -EIO;
    }

    *response = TAKE_PTR(_response);

    return 0;
}

int bf_ensure_dir(const char *dir)
{
    struct stat stats;
    int r;

    bf_assert(dir);

    r = access(dir, R_OK | W_OK);
    if (r && errno == ENOENT) {
        if (mkdir(dir, BF_PERM_755) == 0)
            return 0;

        return bf_err_r(errno, "failed to create directory '%s'", dir);
    }
    if (r)
        return bf_err_r(errno, "no R/W permissions on '%s'", dir);

    if (stat(dir, &stats) != 0 || !S_ISDIR(stats.st_mode))
        return bf_err_r(-EINVAL, "'%s' is not a valid directory", dir);

    return 0;
}

int bf_opendir(const char *path)
{
    _cleanup_close_ int fd = -1;

    bf_assert(path);

    fd = open(path, O_DIRECTORY);
    if (fd < 0)
        return -errno;

    return TAKE_FD(fd);
}

int bf_opendir_at(int parent_fd, const char *dir_name, bool mkdir_if_missing)
{
    _cleanup_close_ int fd = -1;
    int r;

    bf_assert(dir_name);

retry:
    fd = openat(parent_fd, dir_name, O_DIRECTORY);
    if (fd < 0) {
        if (errno != ENOENT || !mkdir_if_missing)
            return -errno;

        r = mkdirat(parent_fd, dir_name, BF_PERM_755);
        if (r)
            return -errno;

        goto retry;
    }

    return TAKE_FD(fd);
}

static void bf_free_dir(DIR **dir)
{
    if (!*dir)
        return;

    closedir(*dir);
    *dir = NULL;
}

#define _free_dir_ __attribute__((__cleanup__(bf_free_dir)))

int bf_rmdir_at(int parent_fd, const char *dir_name, bool recursive)
{
    int r;

    bf_assert(dir_name);

    if (recursive) {
        _cleanup_close_ int child_fd = -1;
        _free_dir_ DIR *dir = NULL;
        struct dirent *entry;

        child_fd = openat(parent_fd, dir_name, O_DIRECTORY);
        if (child_fd < 0) {
            return bf_err_r(errno,
                            "failed to open child directory for removal");
        }

        dir = fdopendir(child_fd);
        if (!dir)
            return bf_err_r(errno, "failed to open DIR from file descriptor");

        while ((entry = readdir(dir))) {
            struct stat stat;

            if (bf_streq(entry->d_name, ".") || bf_streq(entry->d_name, ".."))
                continue;

            if (fstatat(child_fd, entry->d_name, &stat, 0) < 0) {
                return bf_err_r(errno,
                                "failed to fstatat() file '%s' for removal",
                                entry->d_name);
            }

            if (S_ISDIR(stat.st_mode))
                r = bf_rmdir_at(child_fd, entry->d_name, true);
            else
                r = unlinkat(child_fd, entry->d_name, 0) == 0 ? 0 : -errno;
            if (r)
                return bf_err_r(r, "failed to remove '%s'", entry->d_name);
        }
    }

    r = unlinkat(parent_fd, dir_name, AT_REMOVEDIR);
    if (r)
        return -errno;

    return 0;
}
