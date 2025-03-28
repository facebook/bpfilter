/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stddef.h>

#include "core/front.h"
#include "core/helper.h"

struct bf_ns;

#define _cleanup_bf_request_ __attribute__((cleanup(bf_request_free)))

/**
 * @enum bf_request_cmd
 *
 * Defines a request type, so bpfilter can understand the client-specific
 * data contained in the request, and call the proper handler.
 *
 * @var bf_request_cmd::BF_REQ_CUSTOM
 *  Custom request: only the front this request is targeted to is able to
 *  understand what is the actual command. Allows for fronts to implement
 *  new commands.
 */
enum bf_request_cmd
{
    /* Flush the ruleset: remove all the filtering rules defined for a
     * front-end. */
    BF_REQ_RULESET_FLUSH,
    BF_REQ_RULES_SET,
    BF_REQ_RULES_GET,
    BF_REQ_COUNTERS_SET,
    BF_REQ_COUNTERS_GET,
    BF_REQ_CUSTOM,
    _BF_REQ_CMD_MAX,
};

/**
 * @struct bf_request
 *
 * Generic request format sent by the client to the daemon.
 *
 * @var bf_request::front
 *  Front this request is targeted to.
 * @var bf_request::cmd
 *  Command.
 * @var bf_request::ipt_cmd
 *  Custom command for the IPT front.
 * @var bf_request::data_len
 *  Length of the client-specific data.
 * @var bf_request::data
 *  Client-specific data.
 */
struct bf_request
{
    enum bf_front front;
    enum bf_request_cmd cmd;

    /** Namespaces the request is coming from. This field will be automatically
     * populated by the daemon when receiving the request. */
    struct bf_ns *ns;

    union
    {
        struct
        {
            int ipt_cmd;
        };

        struct
        {
            bool cli_with_counters;
        };
    };

    size_t data_len;
    char data[];
};

/**
 * Allocate and initialise a new request.
 *
 * @param request Pointer to the request to allocate. Must be non-NULL.
 * @param data Client-specific data.
 * @param data_len Length of the client-specific data.
 * @return 0 on success or negative errno code on failure.
 */
int bf_request_new(struct bf_request **request, const void *data,
                   size_t data_len);

/**
 * Free a request.
 *
 * If @p request points to a NULL pointer, this function does nothing. Once the
 * function returns, @p request points to a NULL pointer.
 *
 * @param request Request to free. Can't be NULL.
 */
void bf_request_free(struct bf_request **request);

/**
 * Copy a request.
 *
 * @param dest The destination request. It will be allocated during the call.
 *        Can't be NULL.
 * @param src The source request, to copy. Can't be NULL.
 * @return 0 on success, negative error code on failure.
 */
int bf_request_copy(struct bf_request **dest, const struct bf_request *src);

/**
 * Get the total size of the request: request structure and data.
 *
 * @param request Request to get the size of. Can't be NULL.
 * @return Total size of the request.
 */
static inline size_t bf_request_size(const struct bf_request *request)
{
    bf_assert(request);

    return sizeof(struct bf_request) + request->data_len;
}
