/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <sys/types.h>

#define __cleanup_bf_request__ __attribute__((cleanup(bf_request_free)))

enum bf_request_type
{
    BF_REQ_IPT,
    __BF_REQ_TYPE_MAX,
};

struct bf_request
{
    enum bf_request_type type;
    size_t data_len;
    char data[];
};

int bf_request_new(struct bf_request **request, size_t data_len,
                   const char *data);
void bf_request_free(struct bf_request **request);

static inline size_t bf_request_size(struct bf_request *request)
{
    assert(request);

    return sizeof(struct bf_request) + request->data_len;
}
