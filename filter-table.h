/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_FILTER_TABLE_H
#define NET_BPFILTER_FILTER_TABLE_H

#include "table.h"

struct context;

extern const struct table_ops filter_table_ops;

int create_filter_table(struct context *ctx);

#endif // NET_BPFILTER_FILTER_TABLE_H
