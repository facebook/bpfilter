/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_SOCKOPT_H
#define NET_BPFILTER_SOCKOPT_H

struct context;
struct mbox_request;

int handle_sockopt_request(struct context *ctx, const struct mbox_request *req);

#endif // NET_BPFILTER_SOCKOPT_H
