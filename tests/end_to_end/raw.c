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

static const char *message =
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! "
    "Hello, world! Hello, world! Hello, world! Hello, world! Hello, world! ";

int main(void)
{
    __cleanup_bf_request__ struct bf_request *request = NULL;
    __cleanup_bf_response__ struct bf_response *response = NULL;
    int r;

    r = bf_request_new(&request, strlen(message) + 1, message);
    if (r) {
        fprintf(stderr, "bf_request_new() failed: %s\n", strerror(-r));
        return r;
    }

    request->type = BF_REQ_IPT;

    r = bf_send(request, &response);
    if (r) {
        fprintf(stderr, "bf_send() failed: %s\n", strerror(-r));
        return r;
    }

    return EXIT_SUCCESS;
}
