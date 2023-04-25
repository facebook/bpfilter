/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <assert.h>
#include <sys/types.h>

#define __cleanup_bf_response__ __attribute__((cleanup(bf_response_free)))

enum bf_response_type
{
    BF_RES_FAILURE,
    BF_RES_SUCCESS,
    __BF_RES_TYPE_MAX
};

struct bf_response
{
    enum bf_response_type type;

    union
    {
        struct
        {
            size_t data_len;
            char data[];
        };

        struct
        {
            int error;
        };
    };
};

int bf_response_new_success(struct bf_response **response, size_t data_len,
                            const char *data);
int bf_response_new_failure(struct bf_response **response, int error);
void bf_response_free(struct bf_response **response);

static inline size_t bf_response_size(struct bf_response *response)
{
    assert(response);

    return sizeof(struct bf_response) + response->type == BF_RES_SUCCESS ?
               response->data_len :
               0;
}
