// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include "table.h"

#include <linux/err.h>
#include <linux/list.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "logger.h"
#include "rule.h"

static int rule_offset_comparator(const void *x, const void *y)
{
	const struct rule *rule = y;

	return x - (const void *)rule->ipt_entry;
}

static bool table_has_hook(const struct table *table, uint32_t hook)
{
	BUG_ON(hook >= BPFILTER_INET_HOOK_MAX);

	return table->valid_hooks & (1 << hook);
}

static int table_init_rules(struct context *ctx, struct table *table,
			    const struct bpfilter_ipt_replace *ipt_replace)
{
	uint32_t offset;

	table->entries = malloc(table->size);
	if (!table->entries) {
		BFLOG_ERR("out of memory");
		return -ENOMEM;
	}

	memcpy(table->entries, ipt_replace->entries, table->size);

	table->rules = calloc(table->num_rules, sizeof(table->rules[0]));
	if (!table->rules) {
		BFLOG_ERR("out of memory");
		return -ENOMEM;
	}

	offset = 0;
	for (int i = 0; i < table->num_rules; ++i) {
		const struct bpfilter_ipt_entry *ipt_entry;
		int r;

		if (table->size < offset + sizeof(*ipt_entry)) {
			BFLOG_ERR("invalid table size: %d", table->size);
			return -EINVAL;
		}

		ipt_entry = table->entries + offset;

		if ((uintptr_t)ipt_entry % __alignof__(struct bpfilter_ipt_entry)) {
			BFLOG_ERR("invalid alignment for struct ipt_entry");
			return -EINVAL;
		}

		if (table->size < offset + ipt_entry->next_offset) {
			BFLOG_ERR("invalid table size: %d", table->size);
			return -EINVAL;
		}

		r = init_rule(ctx, ipt_entry, &table->rules[i]);
		if (r) {
			BFLOG_ERR("failed to initialize rule: %s",
				  STRERR(r));
			return r;
		}

		table->rules[i].ipt_entry = ipt_entry;
		offset += ipt_entry->next_offset;
	}

	if (offset != ipt_replace->size) {
		BFLOG_ERR("invalid final offset: %d", offset);
		return -EINVAL;
	}

	if (table->num_rules != ipt_replace->num_entries) {
		BFLOG_ERR("mismatch in number of rules: got %d, expected %d",
			  table->num_rules, ipt_replace->num_entries);
		return -EINVAL;
	}

	return 0;
}

static int table_check_hooks(const struct table *table)
{
	uint32_t max_rule_front, max_rule_last;
	bool check = false;

	for (int i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		if (!table_has_hook(table, i))
			continue;

		if (check) {
			if (table->hook_entry[i] <= max_rule_front) {
				BFLOG_ERR("invalid hook entry");
				return -EINVAL;
			}

			if (table->underflow[i] <= max_rule_last) {
				BFLOG_ERR("invalid underflow entry");
				return -EINVAL;
			}
		}

		max_rule_front = table->hook_entry[i];
		max_rule_last = table->underflow[i];
		check = true;
	}

	return 0;
}

static int table_init_hooks(struct table *table,
			    const struct bpfilter_ipt_replace *ipt_replace)
{
	for (int i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		struct rule *rule_front;
		struct rule *rule_last;
		int verdict;

		if (!table_has_hook(table, i))
			continue;

		rule_front = table_find_rule_by_offset(table, ipt_replace->hook_entry[i]);
		rule_last = table_find_rule_by_offset(table, ipt_replace->underflow[i]);

		if (!rule_front || !rule_last) {
			BFLOG_ERR("expected a first and last rule");
			return -EINVAL;
		}

		if (!rule_is_unconditional(rule_last)) {
			BFLOG_ERR("expected unconditional rule");
			return -EINVAL;
		}

		if (!rule_has_standard_target(rule_last)) {
			BFLOG_ERR("expected rule for a standard target");
			return -EINVAL;
		}

		verdict = standard_target_verdict(rule_last->target.ipt_target);
		if (verdict >= 0) {
			BFLOG_ERR("expected a valid standard target verdict: %d",
				  verdict);
			return -EINVAL;
		}

		verdict = convert_verdict(verdict);

		if (verdict != BPFILTER_NF_DROP && verdict != BPFILTER_NF_ACCEPT) {
			BFLOG_ERR("verdict must be either NF_DROP or NF_ACCEPT");
			return -EINVAL;
		}

		table->hook_entry[i] = rule_front - table->rules;
		table->underflow[i] = rule_last - table->rules;
	}

	return table_check_hooks(table);
}

static struct rule *next_rule(const struct table *table, struct rule *rule)
{
	const uint32_t i = rule - table->rules;

	if (table->num_rules <= i + 1) {
		BFLOG_ERR("rule index is out of range");
		return ERR_PTR(-EINVAL);
	}

	++rule;
	rule->came_from = i;

	return rule;
}

static struct rule *backtrack_rule(const struct table *table, struct rule *rule)
{
	uint32_t i = rule - table->rules;
	int prev_i;

	do {
		rule->hook_mask ^= (1 << BPFILTER_INET_HOOK_MAX);
		prev_i = i;
		i = rule->came_from;
		rule->came_from = 0;

		if (i == prev_i)
			return NULL;

		rule = &table->rules[i];
	} while (prev_i == i + 1);

	return next_rule(table, rule);
}

static int table_check_chain(struct table *table, uint32_t hook,
			     struct rule *rule)
{
	uint32_t i = rule - table->rules;

	rule->came_from = i;

	for (;;) {
		bool visited;
		int verdict;

		if (!rule)
			return 0;

		if (IS_ERR(rule))
			return PTR_ERR(rule);

		i = rule - table->rules;

		if (table->num_rules <= i) {
			BFLOG_ERR("rule index is out of range: %d", i);
			return -EINVAL;
		}

		if (rule->hook_mask & (1 << BPFILTER_INET_HOOK_MAX)) {
			BFLOG_ERR("hook index out of range");
			return -EINVAL;
		}

		// already visited
		visited = rule->hook_mask & (1 << hook);
		rule->hook_mask |= (1 << hook) | (1 << BPFILTER_INET_HOOK_MAX);

		if (visited) {
			rule = backtrack_rule(table, rule);
			continue;
		}

		if (!rule_has_standard_target(rule)) {
			rule = next_rule(table, rule);
			continue;
		}

		verdict = standard_target_verdict(rule->target.ipt_target);
		if (verdict > 0) {
			rule = table_find_rule_by_offset(table, verdict);
			if (!rule) {
				BFLOG_ERR("failed to find rule by offset");
				return -EINVAL;
			}

			rule->came_from = i;
			continue;
		}

		if (!rule_is_unconditional(rule)) {
			rule = next_rule(table, rule);
			continue;
		}

		rule = backtrack_rule(table, rule);
	}

	return 0;
}

static int table_check_chains(struct table *table)
{
	int r = 0;

	for (int i = 0, r = 0; !r && i < BPFILTER_INET_HOOK_MAX; ++i) {
		if (table_has_hook(table, i))
			r = table_check_chain(table, i, &table->rules[table->hook_entry[i]]);
	}

	return r;
}

struct table *create_table(struct context *ctx,
			   const struct bpfilter_ipt_replace *ipt_replace)
{
	struct table *table;
	int r;

	table = calloc(1, sizeof(*table));
	if (!table) {
		BFLOG_ERR("out of memory");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&table->list);
	table->valid_hooks = ipt_replace->valid_hooks;
	table->num_rules = ipt_replace->num_entries;
	table->num_counters = ipt_replace->num_counters;
	table->size = ipt_replace->size;

	r = table_init_rules(ctx, table, ipt_replace);
	if (r) {
		BFLOG_ERR("failed to initialise table rules: %s", STRERR(r));
		goto err_free;
	}

	r = table_init_hooks(table, ipt_replace);
	if (r) {
		BFLOG_ERR("failed to initialise table hooks: %s", STRERR(r));
		goto err_free;
	}

	r = table_check_chains(table);
	if (r) {
		BFLOG_ERR("failed to check table chains: %s", STRERR(r));
		goto err_free;
	}

	return table;

err_free:
	free_table(table);

	return ERR_PTR(r);
}

struct rule *table_find_rule_by_offset(const struct table *table,
				       uint32_t offset)
{
	const struct bpfilter_ipt_entry *key;

	key = table->entries + offset;

	return bsearch(key, table->rules, table->num_rules,
		       sizeof(table->rules[0]), rule_offset_comparator);
}

void table_get_info(const struct table *table,
		    struct bpfilter_ipt_get_info *info)
{
	snprintf(info->name, sizeof(info->name), "%s", table->table_ops->name);
	info->valid_hooks = table->valid_hooks;

	for (int i = 0; i < BPFILTER_INET_HOOK_MAX; ++i) {
		const struct rule *rule_front, *rule_last;

		if (!table_has_hook(table, i)) {
			info->hook_entry[i] = 0;
			info->underflow[i] = 0;
			continue;
		}

		rule_front = &table->rules[table->hook_entry[i]];
		rule_last = &table->rules[table->underflow[i]];
		info->hook_entry[i] = (const void *)rule_front->ipt_entry - table->entries;
		info->underflow[i] = (const void *)rule_last->ipt_entry - table->entries;
	}

	info->num_entries = table->num_rules;
	info->size = table->size;
}

void free_table(struct table *table)
{
	if (!table)
		return;

	list_del(&table->list);

	if (table->rules) {
		for (int i = 0; i < table->num_rules; ++i)
			free_rule(&table->rules[i]);
		free(table->rules);
	}

	free(table->entries);
	free(table);
}
