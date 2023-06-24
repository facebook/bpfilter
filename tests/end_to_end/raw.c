/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include <bpfilter/bpfilter.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern const char *strerrordesc_np(int errnum);

static const char *message =
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! ";

int main(void)
{
    _cleanup_bf_request_ struct bf_request *request = NULL;
    _cleanup_bf_response_ struct bf_response *response = NULL;
    int r;

    r = bf_request_new(&request, message, strlen(message) + 1);
    if (r) {
        fprintf(stderr, "bf_request_new() failed: %s\n", strerrordesc_np(-r));
        return r;
    }

    request->front = BF_FRONT_IPT;

    r = bf_send(request, &response);
    if (r) {
        fprintf(stderr, "bf_send() failed: %s\n", strerrordesc_np(-r));
        return r;
    }

    return EXIT_SUCCESS;
}
