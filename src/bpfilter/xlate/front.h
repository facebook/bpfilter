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
 * @var bf_front_ops::setup
 *  Setup the front.
 * @var bf_front_ops::teardown
 *  Teardown the front.
 * @var bf_front_ops::request_handler
 *  Handle a request.
 */
struct bf_front_ops
{
    int (*setup)(void);
    int (*teardown)(void);
    int (*request_handler)(const struct bf_request *request,
                           struct bf_response **response);
    int (*pack)(bf_wpack_t *pack);
    int (*unpack)(bf_rpack_node_t node);
};

/**
 * Retrieve the @ref bf_front_ops structure for a specific front.
 *
 * @param front Front to get the @ref bf_front_ops for.
 * @return
 */
const struct bf_front_ops *bf_front_ops_get(enum bf_front front);
