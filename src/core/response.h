/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/helper.h"
#include "core/pack.h"

#define _free_bf_response_ __attribute__((cleanup(bf_response_free)))

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

/**
 * Allocate a response without copying data.
 *
 * Space will be allocated in the response for @p data_len bytes of data, but
 * no data will be copied, nor will the response's data be initialized.
 *
 * The response's status will be set to 0.
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

int bf_response_new_from_pack(struct bf_response **response, bf_wpack_t *pack);

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

    return sizeof(*response) + response->data_len;
}
