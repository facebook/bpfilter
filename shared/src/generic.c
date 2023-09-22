/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"

static ssize_t _bf_recv_in_buff(int fd, void *buf, size_t buf_len)
{
    ssize_t bytes_read = 0;
    ssize_t r;

    bf_assert(buf);

    do {
        /// @todo Add a timeout to the socket to prevent blocking forever.
        r = read(fd, buf + bytes_read, buf_len - bytes_read);
        if (r < 0) {
            fprintf(stderr, "can't read from the socket: %s\n",
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
            fprintf(stderr, "can't write to socket: %s\n", bf_strerror(errno));
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
        fprintf(stderr, "Failed to send request: %s\n", bf_strerror(errno));
        return -errno;
    }

    if ((size_t)r != bf_request_size(request)) {
        fprintf(stderr,
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
        fprintf(stderr,
                "failed to read request: %lu bytes read, %lu expected\n",
                (size_t)r, sizeof(req));
        return -EIO;
    }

    _request = malloc(bf_request_size(&req));
    if (!_request) {
        fprintf(stderr, "failed to allocate request: %s\n", bf_strerror(errno));
        return -errno;
    }

    memcpy(_request, &req, sizeof(req));

    r = _bf_recv_in_buff(fd, _request->data, _request->data_len);
    if (r < 0)
        return (int)r;

    if ((size_t)r != _request->data_len) {
        fprintf(stderr,
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
        fprintf(stderr, "Failed to send response: %s\n", bf_strerror(errno));
        return -errno;
    }

    if ((size_t)r != bf_response_size(response)) {
        fprintf(stderr,
                "Failed to send response: %lu bytes sent, %ld expected\n", r,
                bf_response_size(response));
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
        fprintf(stderr,
                "failed to read response: %lu bytes read, %lu expected\n",
                (size_t)r, sizeof(res));
        return -EIO;
    }

    _response = malloc(bf_response_size(&res));
    if (!_response) {
        fprintf(stderr, "failed to allocate response: %s\n",
                bf_strerror(errno));
        return -errno;
    }

    memcpy(_response, &res, sizeof(res));

    r = _bf_recv_in_buff(fd, _response->data, _response->data_len);
    if (r < 0)
        return (int)r;

    if ((size_t)r != _response->data_len) {
        fprintf(stderr,
                "failed to read response: %lu bytes read, %lu expected\n",
                (size_t)r, _response->data_len);
        return -EIO;
    }

    *response = TAKE_PTR(_response);

    return 0;
}
