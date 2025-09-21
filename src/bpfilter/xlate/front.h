/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/front.h>
#include <bpfilter/pack.h>

struct bf_request;
struct bf_response;

/**
 * @struct bf_front_ops
 *
 * @todo Front should not implement a callback if it's not needed. E.g.
 * `BF_FRONT_CLI` defines empty `pack` and `unpack` callbacks.
 */
struct bf_front_ops
{
    /// Initialize the front.
    int (*setup)(void);

    /// Teardown the front and free resources.
    int (*teardown)(void);

    /// Handle an incoming request.
    int (*request_handler)(const struct bf_request *request,
                           struct bf_response **response);

    /// Serialize the front's data to restore it later.
    int (*pack)(bf_wpack_t *pack);

    /// Restore the front's data from serialized data.
    int (*unpack)(bf_rpack_node_t node);
};

/**
 * Retrieve the @ref bf_front_ops structure for a specific front.
 *
 * @param front Front to get the @ref bf_front_ops for.
 * @return
 */
const struct bf_front_ops *bf_front_ops_get(enum bf_front front);
