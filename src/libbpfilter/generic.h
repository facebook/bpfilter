/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

#include "core/front.h"
#include "core/request.h"
#include "core/response.h"

int bf_send(const struct bf_request *request, struct bf_response **response);
