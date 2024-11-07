/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#pragma once

struct bf_request;
struct bf_response;

int bf_send(const struct bf_request *request, struct bf_response **response);
