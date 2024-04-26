/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "shared/generic.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "shared/helper.h"

int bf_send(const struct bf_request *request, struct bf_response **response)
{
    _cleanup_close_ int fd = -1;
    struct sockaddr_un addr = {};
    int r;

    bf_assert(request);
    bf_assert(response);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", bf_strerror(errno));
        return -errno;
    }

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0) {
        fprintf(stderr, "Failed to connect to socket: %s\n",
                bf_strerror(errno));
        return -errno;
    }

    r = bf_send_request(fd, request);
    if (r < 0) {
        fprintf(stderr, "Failed to send request: %s\n", bf_strerror(r));
        return r;
    }

    r = bf_recv_response(fd, response);
    if (r < 0) {
        fprintf(stderr, "Failed to receive response: %s\n", bf_strerror(r));
        return r;
    }

    return 0;
}
