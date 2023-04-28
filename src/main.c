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
#include "generator/codegen.h"
#include "shared/generic.h"
#include "shared/helper.h"
#include "shared/request.h"
#include "shared/response.h"
#include "xlate/frontend.h"

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
        const struct bf_frontend *fe;
        __cleanup_close__ int client_fd = -1;
        __cleanup_bf_request__ struct bf_request *request = NULL;
        __cleanup_bf_response__ struct bf_response *response = NULL;

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

        fe = bf_frontend_get(request->type);
        if (fe) {
            bf_list codegens[__BF_HOOK_MAX];

            bf_dbg("Dumping request's data:");
            fe->dump(request->data);

            for (int i = 0; i < __BF_HOOK_MAX; i++) {
                codegens[i] = bf_list_default(
                    {.free = (bf_list_ops_free)bf_codegen_free});
            }

            r = fe->translate(request->data, request->data_len, &codegens);
            if (r < 0)
                return bf_err_code(r, "translation failed");
            else
                bf_info("translation successful!");

            for (int i = 0; i < __BF_HOOK_MAX; i++)
                bf_list_clean(&codegens[i]);

            r = bf_response_new_success(&response, 0, NULL);
            if (r < 0)
                return bf_err_code(r, "bf_response_new_success() failed");
        } else {
            r = bf_response_new_failure(&response, -ENOTSUP);
            if (r < 0)
                return bf_err_code(r, "bf_response_new_failure() failed");
        }

        r = bf_send_response(client_fd, response);
        if (r < 0)
            return bf_err_code(r, "bf_send_response() failed");
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
