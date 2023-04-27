// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "core/context.h"
#include "core/logger.h"
#include "shared/generic.h"
#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"

static struct bf_context context = {};

volatile sig_atomic_t sig_received = 0;

/**
 * @brief Set atomic flag when a signal is received.
 *
 * @param sig Signal number.
 */
void sig_handler(int sig)
{
    UNUSED(sig);

    sig_received = 1;
}

int run(void)
{
    __cleanup_close__ int fd = -1;
    struct sockaddr_un addr = {};
    int r;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return bf_err_code(errno, "socket() failed");

    unlink(BF_SOCKET_PATH); // Remove socket file if it exists.

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BF_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    r = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r < 0)
        return bf_err_code(errno, "bind() failed");

    r = listen(fd, 1);
    if (r < 0)
        return bf_err_code(errno, "listen() failed");

    bf_info("Starting to accept connections...");

    while (!sig_received) {
        __cleanup_close__ int client_fd = -1;
        __cleanup_bf_request__ struct bf_request *request = NULL;
        __cleanup_bf_response__ struct bf_response *dummy = NULL;

        client_fd = accept(fd, NULL, NULL);
        if (client_fd < 0) {
            if (sig_received) {
                bf_info("Received signal, exiting...");
                continue;
            }

            return bf_err_code(errno, "accept() failed");
        }

        r = bf_recv_request(client_fd, &request);
        if (r < 0)
            return bf_err_code(r, "bf_recv_request() failed");

        r = bf_response_new_failure(&dummy, ENOMEM);
        if (r < 0)
            return bf_err_code(r, "bf_response_new_failure() failed");

        r = bf_send_response(client_fd, dummy);
    }

    return 0;
}

int main(void)
{
    int r;

    struct sigaction sa = {
        .sa_handler = sig_handler,
    };

    if (sigaction(SIGINT, &sa, NULL) < 0)
        return bf_err_code(errno, "sigaction() failed");

    if (sigaction(SIGTERM, &sa, NULL) < 0)
        return bf_err_code(errno, "sigaction() failed");

    bf_context_init(&context);

    r = run();
    if (r < 0)
        bf_err_code(r, "run() failed");

    bf_context_clean(&context);

    return r;
}
