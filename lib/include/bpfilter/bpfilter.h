/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <bpfilter/shared/request.h>
#include <bpfilter/shared/response.h>

/**
 * @brief Send a request to the daemon and receive the response.
 *
 * @param request Request to send to the daemon. Caller keep ownership of the
 *  request. Can't be NULL.
 * @param response Response received from the daemon. It will be allocated by
 *  the function and the caller will be responsible for freeing it. Can't be
 *  NULL.
 * @return 0 on success, negative errno value on error.
 */
int bf_send(struct bf_request *request, struct bf_response **response);
