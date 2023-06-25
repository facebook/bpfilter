/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"

#define _RECV_BUF_SIZE 64

static int _bf_recv_in_buff(int fd, char **buf, size_t *buf_len)
{
    _cleanup_free_ char *_buf = NULL;
    size_t buf_capacity = _RECV_BUF_SIZE;
    size_t _buf_len = 0;
    ssize_t r;

    assert(buf);
    assert(buf_len);

    do {
        r = bf_realloc((void **)&_buf, buf_capacity <<= 1);
        if (r < 0)
            return (int)r;

        r = recv(fd, _buf + _buf_len, buf_capacity - _buf_len, 0);
        if (r < 0) {
            fprintf(stderr, "recv() failed: %s\n", bf_strerror(errno));
            return -errno;
        }

        _buf_len += r;
    } while (r && _buf_len == buf_capacity);

    *buf = TAKE_PTR(_buf);
    *buf_len = _buf_len;

    return 0;
}

int bf_send_request(int fd, const struct bf_request *request)
{
    ssize_t r;

    assert(request);

    r = send(fd, request, bf_request_size(request), 0);
    if (r < 0) {
        fprintf(stderr, "Failed to send request: %s\n", bf_strerror(errno));
        return -errno;
    }

    if ((size_t)r != bf_request_size(request)) {
        fprintf(stderr,
                "Failed to send request: %lu bytes sent, %ld expected\n", r,
                bf_request_size(request));
        return -EIO;
    }

    return 0;
}

int bf_recv_request(int fd, struct bf_request **request)
{
    _cleanup_bf_request_ struct bf_request *_request = NULL;
    _cleanup_bf_request_ struct bf_request *_oversized_request = NULL;
    _cleanup_free_ char *buf = NULL;
    size_t buf_len;
    int r;

    assert(request);

    r = _bf_recv_in_buff(fd, &buf, &buf_len);
    if (r < 0)
        return r;

    if (buf_len < sizeof(*_request)) {
        fprintf(stderr, "Received request is too small\n");
        return -EINVAL;
    }

    _oversized_request = (struct bf_request *)TAKE_PTR(buf);
    if (bf_request_size(_oversized_request) > buf_len) {
        fprintf(stderr, "Received request is too large\n");
        return -EINVAL;
    }

    r = bf_request_copy(&_request, _oversized_request);
    if (r < 0) {
        fprintf(stderr, "Failed to allocate request: %s\n", bf_strerror(r));
        return r;
    }

    *request = TAKE_PTR(_request);

    return 0;
}

int bf_send_response(int fd, struct bf_response *response)
{
    ssize_t r;

    assert(response);

    r = send(fd, response, bf_response_size(response), 0);
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
    _cleanup_bf_response_ struct bf_response *_response = NULL;
    _cleanup_bf_response_ struct bf_response *_oversized_response = NULL;
    _cleanup_free_ char *buf = NULL;
    size_t buf_len;
    int r;

    assert(response);

    r = _bf_recv_in_buff(fd, &buf, &buf_len);
    if (r < 0)
        return r;

    if (buf_len < sizeof(*_response)) {
        fprintf(stderr, "Received response is too small\n");
        return -EINVAL;
    }

    _oversized_response = (struct bf_response *)TAKE_PTR(buf);
    if (bf_response_size(_oversized_response) > buf_len) {
        fprintf(stderr, "Received response is too large\n");
        return -EINVAL;
    }

    r = bf_response_copy(&_response, _oversized_response);
    if (r < 0) {
        fprintf(stderr, "Failed to allocate response: %s\n", bf_strerror(r));
        return r;
    }

    *response = TAKE_PTR(_response);

    return 0;
}
