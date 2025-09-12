/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "core/response.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "core/dynbuf.h"
#include "core/helper.h"

/**
 * @brief Response message sent from the daemon to the client.
 */
struct bf_response
{
    /** Response status: 0 on success, or a negative error value on failure. */
    int status;

    /** Number of bytes stored in `data`. */
    size_t data_len;

    /** Data carried by the response. */
    char data[];
};

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

int bf_response_new_from_dynbuf(struct bf_response **response,
                                struct bf_dynbuf *dynbuf)
{
    struct bf_response *tmpres;

    bf_assert(response);
    bf_assert(dynbuf);

    if (dynbuf->len < sizeof(*tmpres))
        return -EINVAL;

    tmpres = dynbuf->data;
    if (bf_response_size(tmpres) != dynbuf->len)
        return -EINVAL;

    *response = bf_dynbuf_take(dynbuf);

    return 0;
}

int bf_response_new_from_pack(struct bf_response **response, bf_wpack_t *pack)
{
    const void *data;
    size_t data_len;
    int r;

    bf_assert(response);
    bf_assert(pack);

    if (!bf_wpack_is_valid(pack))
        return -EINVAL;

    r = bf_wpack_get_data(pack, &data, &data_len);
    if (r)
        return r;

    return bf_response_new_success(response, data, data_len);
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

int bf_response_status(const struct bf_response *response)
{
    bf_assert(response);

    return response->status;
}

const void *bf_response_data(const struct bf_response *response)
{
    bf_assert(response);

    return response->data;
}

size_t bf_response_data_len(const struct bf_response *response)
{
    bf_assert(response);

    return response->data_len;
}

size_t bf_response_size(const struct bf_response *response)
{
    bf_assert(response);

    return sizeof(*response) + response->data_len;
}
