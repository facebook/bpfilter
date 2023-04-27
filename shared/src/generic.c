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
#include <unistd.h>

#include "shared/helper.h"
#include "shared/mem.h"
#include "shared/request.h"
#include "shared/response.h"

static int bf_recv_in_buff(int fd, char **buf, size_t *buf_len)
{
    __cleanup_free__ char *_buf = NULL;
    size_t buf_capacity = 64;
    size_t _buf_len = 0;
    int r;

    assert(buf);
    assert(buf_len);

    do {
        _buf = realloc(_buf, buf_capacity <<= 1);
        if (!_buf)
            return -ENOMEM;

        r = recv(fd, _buf + _buf_len, buf_capacity - _buf_len, 0);
        if (r < 0) {
            fprintf(stderr, "recv() failed: %s\n", strerror(errno));
            return -errno;
        }

        _buf_len += r;
    } while (r > 0 && _buf_len == buf_capacity);

    *buf = TAKE_PTR(_buf);
    *buf_len = _buf_len;

    return 0;
}

int bf_send_request(int fd, const struct bf_request *request)
{
    int r;

    assert(request);

    r = send(fd, request, bf_request_size(request), 0);
    if (r < 0) {
        fprintf(stderr, "Failed to send request: %s\n", strerror(errno));
        return -errno;
    } else if ((size_t)r != bf_request_size(request)) {
        fprintf(stderr, "Failed to send request: %d bytes sent, %ld expected\n",
                r, bf_request_size(request));
        return -EIO;
    }

    return 0;
}

int bf_recv_request(int fd, struct bf_request **request)
{
    __cleanup_bf_request__ struct bf_request *_request = NULL;
    __cleanup_bf_request__ struct bf_request *_oversized_request = NULL;
    __cleanup_free__ char *buf = NULL;
    size_t buf_len;
    int r;

    assert(request);

    r = bf_recv_in_buff(fd, &buf, &buf_len);
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

    r = bf_request_new(&_request, _oversized_request->data_len,
                       _oversized_request->data);
    if (r < 0) {
        fprintf(stderr, "Failed to allocate request: %s\n", strerror(-r));
        return r;
    }

    *request = TAKE_PTR(_request);

    return 0;
}

int bf_send_response(int fd, struct bf_response *response)
{
    int r;

    assert(response);

    r = send(fd, response, bf_response_size(response), 0);
    if (r < 0) {
        fprintf(stderr, "Failed to send response: %s\n", strerror(errno));
        return -errno;
    } else if ((size_t)r != bf_response_size(response)) {
        fprintf(stderr,
                "Failed to send response: %d bytes sent, %ld expected\n", r,
                bf_response_size(response));
        return -EIO;
    }

    return 0;
}

int bf_recv_response(int fd, struct bf_response **response)
{
    __cleanup_bf_response__ struct bf_response *_response = NULL;
    __cleanup_bf_response__ struct bf_response *_oversized_response = NULL;
    __cleanup_free__ char *buf = NULL;
    size_t buf_len;
    int r;

    assert(response);

    r = bf_recv_in_buff(fd, &buf, &buf_len);
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

    r = bf_response_new_raw(&_response, _oversized_response->data,
                            _oversized_response->data_len);
    if (r < 0) {
        fprintf(stderr, "Failed to allocate response: %s\n", strerror(-r));
        return r;
    }

    *response = TAKE_PTR(_response);

    return 0;
}
