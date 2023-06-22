/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "shared/response.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "shared/helper.h"

int bf_response_new_success(struct bf_response **response, const char *data,
                            size_t data_len)
{
    _cleanup_bf_response_ struct bf_response *_response = NULL;

    assert(response);
    assert(!(!!data ^ !!data_len));

    _response = calloc(1, sizeof(*_response) + data_len);
    if (!_response)
        return -ENOMEM;

    _response->type = BF_RES_SUCCESS;
    _response->data_len = data_len;
    bf_memcpy(_response->data, data, data_len);

    *response = TAKE_PTR(_response);

    return 0;
}

int bf_response_new_failure(struct bf_response **response, int error)
{
    _cleanup_bf_response_ struct bf_response *_response = NULL;

    assert(response);

    _response = calloc(1, sizeof(*_response));
    if (!_response)
        return -ENOMEM;

    _response->type = BF_RES_FAILURE;
    _response->error = error;

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
    _cleanup_bf_response_ struct bf_response *_response = NULL;

    assert(dest);
    assert(src);

    _response = bf_memdup(src, bf_response_size(src));
    if (!_response)
        return -ENOMEM;

    *dest = TAKE_PTR(_response);

    return 0;
}
