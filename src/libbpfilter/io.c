/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/io.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "bpfilter/dynbuf.h"
#include "bpfilter/helper.h"
#include "bpfilter/logger.h"
#include "bpfilter/request.h"
#include "bpfilter/response.h"

#define BF_PERM_755 (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define BF_MSG_BUF_SIZE 1024U

static int _bf_recv_in_buff(int fd, struct bf_dynbuf *buf)
{
    size_t remaining = 1;

    assert(buf);

    while (remaining > 0) {
        ssize_t r;
        uint8_t tmpbuf[BF_MSG_BUF_SIZE];

        struct iovec iov[2] = {
            {
                .iov_base = &remaining,
                .iov_len = sizeof(remaining),
            },
            {
                .iov_base = tmpbuf,
                .iov_len = BF_MSG_BUF_SIZE,
            },
        };

        struct msghdr msg = {
            .msg_iov = iov,
            .msg_iovlen = ARRAY_SIZE(iov),
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_control = NULL,
            .msg_controllen = 0,
        };

        r = recvmsg(fd, &msg, 0);
        if (r < 0)
            return bf_err_r(-errno, "failed to receive data");
        if ((size_t)r < sizeof(remaining))
            return bf_err_r(-EIO, "received partial data");

        r = bf_dynbuf_write(buf, tmpbuf, r - sizeof(remaining));
        if (r) {
            return bf_err_r((int)r,
                            "failed to write received data to dynamic buffer");
        }
    }

    return 0;
}

static int _bf_send_from_buff(int fd, void *buf, size_t buf_len)
{
    size_t sent = 0;

    assert(buf);

    while (buf_len > 0) {
        size_t send_size = bf_min(BF_MSG_BUF_SIZE, buf_len);
        ssize_t r;
        size_t rem = buf_len - send_size;

        struct iovec iov[2] = {
            {
                .iov_base = &rem,
                .iov_len = sizeof(buf_len),
            },
            {
                .iov_base = buf + sent,
                .iov_len = send_size,
            },
        };

        struct msghdr msg = {
            .msg_iov = iov,
            .msg_iovlen = ARRAY_SIZE(iov),
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_control = NULL,
            .msg_controllen = 0,
        };

        r = sendmsg(fd, &msg, MSG_NOSIGNAL);
        if (r < 0)
            return bf_err_r(-errno, "failed to send data from buff");
        if ((size_t)r != send_size + sizeof(buf_len))
            return bf_err_r(-EIO, "sent partial data");

        sent += (size_t)r - sizeof(buf_len);
        buf_len -= (size_t)r - sizeof(buf_len);
    }

    return 0;
}

/**
 * Send a request to the given file descriptor.
 *
 * @param fd File descriptor to send the request to. Must be a valid file
 *        descriptor.
 * @param request Request to send. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_send_request(int fd, const struct bf_request *request)
{
    int r;

    assert(request);

    r = _bf_send_from_buff(fd, (void *)request, bf_request_size(request));
    if (r < 0)
        return bf_err_r(r, "failed to send request");

    return 0;
}

int bf_recv_request(int fd, struct bf_request **request)
{
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    int r;

    assert(request);

    r = _bf_recv_in_buff(fd, &dynbuf);
    if (r)
        return bf_err_r(r, "failed to receive request");

    r = bf_request_new_from_dynbuf(request, &dynbuf);
    if (r)
        return bf_err_r((int)r, "failed to create request from buffer");

    return 0;
}

int bf_send_response(int fd, struct bf_response *response)
{
    int r;

    assert(response);

    r = _bf_send_from_buff(fd, (void *)response, bf_response_size(response));
    if (r < 0)
        return bf_err_r(r, "failed to send response");

    return 0;
}

/**
 * Received a response from the file descriptor.
 *
 * @param fd File descriptor to receive the response from. Must be a valid file
 *        descriptor.
 * @param response Response to receive. Can't be NULL. Will be allocated by the
 *        function.
 * @return 0 on success, negative error code on failure.
 */
static int _bf_recv_response(int fd, struct bf_response **response)
{
    _clean_bf_dynbuf_ struct bf_dynbuf dynbuf = bf_dynbuf_default();
    int r;

    assert(response);

    r = _bf_recv_in_buff(fd, &dynbuf);
    if (r)
        return bf_err_r((int)r, "failed to receive response");

    r = bf_response_new_from_dynbuf(response, &dynbuf);
    if (r)
        return bf_err_r((int)r, "failed to create response from buffer");

    return 0;
}

int bf_ensure_dir(const char *dir)
{
    struct stat stats;
    int r;

    assert(dir);

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

    assert(path);

    fd = open(path, O_DIRECTORY);
    if (fd < 0)
        return -errno;

    return TAKE_FD(fd);
}

int bf_opendir_at(int parent_fd, const char *dir_name, bool mkdir_if_missing)
{
    _cleanup_close_ int fd = -1;
    int r;

    assert(dir_name);

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

    assert(dir_name);

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

int bf_acquire_lock(const char *path)
{
    _cleanup_close_ int fd = -1;

    assert(path);

    fd = open(path, O_CREAT | O_RDWR, BF_PERM_755);
    if (fd < 0)
        return -errno;

    if (flock(fd, LOCK_EX | LOCK_NB) < 0)
        return -errno;

    return TAKE_FD(fd);
}

int bf_send_fd(int sock_fd, int fd)
{
    char dummy = 'X';
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &dummy, .iov_len = 1};
    ssize_t r;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    r = sendmsg(sock_fd, &msg, 0);
    if (r < 0)
        return bf_err_r(errno, "failed to send file descriptor");

    return 0;
}

/**
 * @brief Receive a file descriptor over a Unix Domain Socket.
 *
 * @param sock_fd Socket file descriptor to receive the file descriptor through.
 * @return A file descriptor, or a negative error value on failure. The caller
 *         owns the file descriptor.
 */
static int _bf_recv_fd(int sock_fd)
{
    int fd;
    char dummy;
    struct cmsghdr *cmsg;
    struct msghdr msg = {0};
    char buf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = {.iov_base = &dummy, .iov_len = 1};
    ssize_t r;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    r = recvmsg(sock_fd, &msg, 0);
    if (r < 0)
        return bf_err_r(errno, "failed to receive file descriptor");

    cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg)
        return bf_err_r(-ENOENT, "no control message received");
    if (cmsg->cmsg_level != SOL_SOCKET)
        return bf_err_r(-EINVAL, "invalid control message level");
    if (cmsg->cmsg_type != SCM_RIGHTS)
        return bf_err_r(-EINVAL, "invalid control message type");

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

    return fd;
}

int bf_connect_to_daemon(void)
{
    _cleanup_close_ int fd = -1;
    struct sockaddr_un addr = {};
    int r;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return bf_err_r(errno, "bpfilter: can't create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "bpfilter: failed to connect to socket");

    return TAKE_FD(fd);
}

int bf_send(int fd, const struct bf_request *request,
            struct bf_response **response, int *recv_fd)
{
    _cleanup_close_ int _recv_fd = -1;
    int r;

    assert(request);
    assert(response);

    r = _bf_send_request(fd, request);
    if (r < 0)
        return bf_err_r(r, "bpfilter: failed to send request to the daemon");

    if (recv_fd) {
        _recv_fd = _bf_recv_fd(fd);
        if (_recv_fd < 0)
            return bf_err_r(_recv_fd, "failed to receive file descriptor");
    }

    r = _bf_recv_response(fd, response);
    if (r < 0) {
        return bf_err_r(r,
                        "bpfilter: failed to receive response from the daemon");
    }

    if (recv_fd)
        *recv_fd = TAKE_FD(_recv_fd);

    return 0;
}
