/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#ifndef NET_BPFILTER_TABLE_H
#define NET_BPFILTER_TABLE_H

#include "../../include/uapi/linux/bpfilter.h"

#include <linux/types.h>

#include <search.h>
#include <stdint.h>

struct context;
struct rule;
struct table;

struct table_ops {
	char name[BPFILTER_XT_TABLE_MAXNAMELEN];
	struct table *(*create)(struct context *ctx,
				const struct bpfilter_ipt_replace *ipt_replace);
	int (*codegen)(struct context *ctx, struct table *table);
	int (*install)(struct context *ctx, struct table *table);
	void (*uninstall)(struct context *ctx, struct table *table);
	void (*free)(struct table *table);
	void (*update_counters)(struct table *table);
};

struct table {
	const struct table_ops *table_ops;
	uint32_t valid_hooks;
	uint32_t num_rules;
	uint32_t num_counters;
	uint32_t size;
	uint32_t hook_entry[BPFILTER_INET_HOOK_MAX];
	uint32_t underflow[BPFILTER_INET_HOOK_MAX];
	struct rule *rules;
	void *entries;
	void *ctx;
	struct list_head list;
};

struct table_index {
	struct hsearch_data map;
	struct list_head list;
};

struct table *create_table(struct context *ctx,
			   const struct bpfilter_ipt_replace *ipt_replace);
struct rule *table_find_rule_by_offset(const struct table *table,
				       uint32_t offset);
void table_get_info(const struct table *table,
		    struct bpfilter_ipt_get_info *info);
void free_table(struct table *table);

#endif // NET_BPFILTER_TABLE_H
