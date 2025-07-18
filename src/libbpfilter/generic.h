/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_request;
struct bf_response;

int bf_send(const struct bf_request *request, struct bf_response **response);

/**
 * @brief Send a request to the daemon, receive a file descriptor and a
 * response.
 *
 * Some request types require the daemon to return a file descriptor
 * (e.g. `BF_REQ_CHAIN_LOGS_FD`), which the standard `bf_send()` function cant'
 * do.
 *
 * @pre
 * - `request` is a valid, non-NULL request
 * - `response != NULL`
 *
 * @param request Request to send to the daemon.
 * @param response Response received from the daemon, allocated by
 *        `bf_send_with_fd()`.
 * @return A valid file descriptor, or a negative error value on failure.
 *         `response` and the returned file descriptor are owned by the caller.
 */
int bf_send_with_fd(const struct bf_request *request,
                    struct bf_response **response);
