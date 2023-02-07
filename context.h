/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_CONTEXT_H
#define NET_BPFILTER_CONTEXT_H

#include <search.h>

#include "table.h"

struct context {
	struct hsearch_data match_ops_map;
	struct hsearch_data target_ops_map;
	struct hsearch_data table_ops_map;
	struct table_index table_index;
};

int create_context(struct context *ctx);
void free_context(struct context *ctx);

#endif // NET_BPFILTER_CONTEXT_H
