/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/response.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/helper.h"

int bf_response_new_raw(struct bf_response **response, size_t data_len)
{
    bf_assert(response);

    *response = malloc(sizeof(**response) + data_len);
    if (!*response)
        return -ENOMEM;

    (*response)->status = 0;

    return 0;
}

int bf_response_new_success(struct bf_response **response, const char *data,
                            size_t data_len)
{
    _free_bf_response_ struct bf_response *_response = NULL;

    bf_assert(response);
    bf_assert(!(!!data ^ !!data_len));

    _response = calloc(1, sizeof(*_response) + data_len);
    if (!_response)
        return -ENOMEM;

    _response->status = 0;
    _response->data_len = data_len;
    bf_memcpy(_response->data, data, data_len);

    *response = TAKE_PTR(_response);

    return 0;
}

int bf_response_new_failure(struct bf_response **response, int error)
{
    _free_bf_response_ struct bf_response *_response = NULL;

    bf_assert(response);

    _response = calloc(1, sizeof(*_response));
    if (!_response)
        return -ENOMEM;

    _response->status = error;

    *response = TAKE_PTR(_response);

    return 0;
}

void bf_response_free(struct bf_response **response)
{
    free(*response);
    *response = NULL;
}

int bf_response_copy(struct bf_response **dest, const struct bf_response *src)
{
    _free_bf_response_ struct bf_response *_response = NULL;

    bf_assert(dest);
    bf_assert(src);

    _response = bf_memdup(src, bf_response_size(src));
    if (!_response)
        return -ENOMEM;

    *dest = TAKE_PTR(_response);

    return 0;
}
