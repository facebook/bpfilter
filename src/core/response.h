/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/helper.h"

#define _free_bf_response_ __attribute__((cleanup(bf_response_free)))

/**
 * @enum bf_response_type
 *
 * Type of response received from the daemon.
 */
enum bf_response_type
{
    BF_RES_SUCCESS,
    BF_RES_FAILURE,
    _BF_RES_MAX
};

/**
 * @struct bf_response
 *
 * Response received from the daemon.
 *
 * @var bf_response::type
 *  Type of the response: success or failure.
 * @var bf_response::data_len
 *  Length of the data in the response.
 * @var bf_response::data
 *  Data in the response.
 * @var bf_response::error
 *  Error code.
 */
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

/**
 * Allocate a response without copying data.
 *
 * Space will be allocated in the response for @p data_len bytes of data, but
 * no data will be copied, nor will the response's data be initialized.
 *
 * The response's type will be set to BF_RES_SUCCESS.
 *
 * @param response Pointer to the response to allocate. Must be non-NULL.
 * @param data_len Size of the data to allocate.
 * @return 0 on success, or negative errno code on failure.
 */
int bf_response_new_raw(struct bf_response **response, size_t data_len);

/**
 * Allocate and initialise a new successful response.
 *
 * @param response Pointer to the response to allocate. Must be non-NULL.
 * @param data Client-specific data.
 * @param data_len Length of the client-specific data.
 * @return 0 on success, or negative errno code on failure.
 */
int bf_response_new_success(struct bf_response **response, const char *data,
                            size_t data_len);

/**
 * Allocate and initialise a new failure response.
 *
 * @param response Pointer to the response to allocate. Must be non-NULL.
 * @param error Error code that store in the response.
 * @return 0 on success, or negative errno code on failure.
 */
int bf_response_new_failure(struct bf_response **response, int error);

/**
 * Free a response.
 *
 * If @p response points to a NULL pointer, this function does nothing. Once the
 * function returns, @p response points to a NULL pointer.
 *
 * @param response Response to free. Can't be NULL.
 */
void bf_response_free(struct bf_response **response);

/**
 * Copy a response.
 *
 * @param dest The destination response. It will be allocated during the call.
 *        Can't be NULL.
 * @param src The source response, to copy. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_response_copy(struct bf_response **dest, const struct bf_response *src);

/**
 * Get the total size of the response: request structure and data (if any).
 *
 * @param response Response to get the size of. Can't be NULL.
 * @return Total size of the response.
 */
static inline size_t bf_response_size(const struct bf_response *response)
{
    bf_assert(response);

    return sizeof(struct bf_response) +
           (response->type == BF_RES_SUCCESS ? response->data_len : 0);
}
