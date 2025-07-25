/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "libbpfilter/generic.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "core/helper.h"
#include "core/io.h"
#include "core/logger.h"

int bf_send(const struct bf_request *request, struct bf_response **response)
{
    _cleanup_close_ int fd = -1;
    struct sockaddr_un addr = {};
    int r;

    bf_assert(request);
    bf_assert(response);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return bf_err_r(errno, "bpfilter: can't create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "bpfilter: failed to connect to socket");

    r = bf_send_request(fd, request);
    if (r < 0)
        return bf_err_r(r, "bpfilter: failed to send request to the daemon");

    r = bf_recv_response(fd, response);
    if (r < 0) {
        return bf_err_r(r,
                        "bpfilter: failed to receive response from the daemon");
    }

    return 0;
}

int bf_send_with_fd(const struct bf_request *request,
                    struct bf_response **response)
{
    bf_assert(request && response);

    _cleanup_close_ int sock_fd = -1;
    _cleanup_close_ int fd = -1;
    struct sockaddr_un addr = {};
    int r;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return bf_err_r(errno, "failed to create socket");

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_r(errno, "failed to connect to socket");

    r = bf_send_request(sock_fd, request);
    if (r < 0)
        return bf_err_r(r, "failed to send request to the daemon");

    fd = bf_recv_fd(sock_fd);
    if (fd < 0)
        return bf_err_r(fd, "failed to receive file descriptor");

    r = bf_recv_response(sock_fd, response);
    if (r < 0)
        return bf_err_r(r, "failed to receive response from the daemon");

    return TAKE_FD(fd);
}
