/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include <stdio.h> // NOLINT: header is used in bf_err().

#include "core/helper.h"
#include "core/request.h"
#include "core/response.h"

#define bf_err(r, fmt, ...)                                                    \
    ({                                                                         \
        (void)fprintf(stderr, fmt ": %s\n", ##__VA_ARGS__, bf_strerror(r));    \
        r < 0 ? r : -r;                                                        \
    })

int bf_send(const struct bf_request *request, struct bf_response **response);
