// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include "sockopt.h"

#include <linux/err.h>
#include <linux/list.h>
#include <linux/netfilter/x_tables.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "logger.h"
#include "map-common.h"
#include "match.h"
#include "msgfmt.h"
#include "table.h"

static int pvm_read(pid_t pid, void *to, const void *from, size_t count)
{
	ssize_t total_bytes;
	const struct iovec l_iov = {
		.iov_base = to,
		.iov_len = count
	};
	const struct iovec r_iov = {
		.iov_base = (void *)from,
		.iov_len = count
	};

	total_bytes = process_vm_readv(pid, &l_iov, 1, &r_iov, 1, 0);
	if (total_bytes == -1) {
		BFLOG_ERR("failed to read from PID %d: %s", pid, STRERR(errno));
		return -errno;
	}

	if (total_bytes != count) {
		BFLOG_ERR("invalid amount a data transferred: %ld bytes, %ld expected",
			  total_bytes, count);
		return -EFAULT;
	}

	return 0;
}

static int pvm_read_from_offset(pid_t pid, void *to, const void *from,
				size_t offset, size_t count)
{
	return pvm_read(pid, to + offset, from + offset, count);
}

static int pvm_write(pid_t pid, void *to, const void *from, size_t count)
{
	ssize_t total_bytes;
	const struct iovec l_iov = {
		.iov_base = (void *)from,
		.iov_len = count
	};
	const struct iovec r_iov = {
		.iov_base = to,
		.iov_len = count
	};

	total_bytes = process_vm_writev(pid, &l_iov, 1, &r_iov, 1, 0);
	if (total_bytes == -1) {
		BFLOG_ERR("failed to write to PID %d: %s", pid, STRERR(errno));
		return -errno;
	}

	if (total_bytes != count) {
		BFLOG_ERR("invalid amount a data transferred: %ld bytes, %ld expected",
			  total_bytes, count);
		return -EFAULT;
	}

	return 0;
}

static int read_ipt_get_info(const struct mbox_request *req,
			     struct bpfilter_ipt_get_info *info)
{
	int r;

	if (req->len != sizeof(*info)) {
		BFLOG_ERR("invalid request size: %d", req->len);
		return -EINVAL;
	}

	r = pvm_read(req->pid, info, (const void *)req->addr, sizeof(*info));
	if (r) {
		BFLOG_ERR("failed to read from PID %d", req->pid);
		return r;
	}

	info->name[sizeof(info->name) - 1] = '\0';

	return 0;
}

static int sockopt_get_info(struct context *ctx, const struct mbox_request *req)
{
	struct bpfilter_ipt_get_info info;
	struct table *table;
	int r;

	if (req->len != sizeof(info)) {
		BFLOG_ERR("invalid request size: %d", req->len);
		return -EINVAL;
	}

	r = read_ipt_get_info(req, &info);
	if (r) {
		BFLOG_ERR("failed to read struct ipt_get_info : %s", STRERR(r));
		return r;
	}

	table = map_find(&ctx->table_index.map, info.name);
	if (IS_ERR(table)) {
		BFLOG_ERR("cannot find table '%s' in map", info.name);
		return -ENOENT;
	}

	table_get_info(table, &info);

	return pvm_write(req->pid, (void *)req->addr, &info, sizeof(info));
}

static int read_ipt_get_entries(const struct mbox_request *req,
				struct bpfilter_ipt_get_entries *entries)
{
	int r;

	if (req->len < sizeof(*entries)) {
		BFLOG_ERR("invalid request size: %d", req->len);
		return -EINVAL;
	}

	r = pvm_read(req->pid, entries, (const void *)req->addr,
		     sizeof(*entries));
	if (r) {
		BFLOG_ERR("failed to read from PID %d", req->pid);
		return r;
	}

	entries->name[sizeof(entries->name) - 1] = '\0';

	return 0;
}

static int sockopt_get_entries(struct context *ctx,
			       const struct mbox_request *req)
{
	struct bpfilter_ipt_get_entries get_entries;
	struct bpfilter_ipt_get_entries *entries;
	struct table *table;
	int r;

	r = read_ipt_get_entries(req, &get_entries);
	if (r) {
		BFLOG_ERR("failed to read struct ipt_get_entries: %s",
			  STRERR(r));
		return r;
	}

	table = map_find(&ctx->table_index.map, get_entries.name);
	if (IS_ERR(table)) {
		BFLOG_ERR("cannot find table '%s' in map", get_entries.name);
		return -ENOENT;
	}

	if (get_entries.size != table->size) {
		BFLOG_ERR("table '%s' get entries size mismatch",
			  get_entries.name);
		return -EINVAL;
	}

	entries = (struct bpfilter_ipt_get_entries *)req->addr;

	table->table_ops->update_counters(table);

	r = pvm_write(req->pid, entries->name, table->table_ops->name,
		      sizeof(entries->name));
	if (r) {
		BFLOG_ERR("failed to write to PID %d", req->pid);
		return r;
	}

	r = pvm_write(req->pid, &entries->size, &table->size,
		      sizeof(table->size));
	if (r) {
		BFLOG_ERR("failed to write to PID %d", req->pid);
		return r;
	}

	return pvm_write(req->pid, entries->entries, table->entries, table->size);
}

static int read_ipt_get_revision(const struct mbox_request *req,
				 struct bpfilter_ipt_get_revision *revision)
{
	int r;

	if (req->len != sizeof(*revision)) {
		BFLOG_ERR("invalid request size: %d", req->len);
		return -EINVAL;
	}

	r = pvm_read(req->pid, revision, (const void *)req->addr,
		     sizeof(*revision));
	if (r) {
		BFLOG_ERR("failed to read to PID %d", req->pid);
		return r;
	}

	revision->name[sizeof(revision->name) - 1] = '\0';

	return 0;
}

static int sockopt_get_revision_match(struct context *ctx,
				      const struct mbox_request *req)
{
	struct bpfilter_ipt_get_revision get_revision;
	const struct match_ops *found;
	int r;

	r = read_ipt_get_revision(req, &get_revision);
	if (r) {
		BFLOG_ERR("failed to read struct ipt_get_revision: %s", STRERR(r));
		return r;
	}

	found = map_find(&ctx->match_ops_map, get_revision.name);
	if (IS_ERR(found)) {
		BFLOG_ERR("cannot find match '%s' in map", get_revision.name);
		return PTR_ERR(found);
	}

	return found->revision;
}

static int sockopt_get_revision_target(struct context *ctx,
				       const struct mbox_request *req)
{
	struct bpfilter_ipt_get_revision get_revision;
	const struct match_ops *found;
	int r;

	r = read_ipt_get_revision(req, &get_revision);
	if (r) {
		BFLOG_ERR("failed to read struct ipt_get_revision: %s",
			  STRERR(r));
		return r;
	}

	found = map_find(&ctx->target_ops_map, get_revision.name);
	if (IS_ERR(found)) {
		BFLOG_ERR("cannot find target '%s' in map", get_revision.name);
		return PTR_ERR(found);
	}

	return found->revision;
}

static struct bpfilter_ipt_replace *read_ipt_replace(struct context *ctx,
						     const struct mbox_request *req)
{
	struct bpfilter_ipt_replace ipt_header;
	struct bpfilter_ipt_replace *ipt_replace;
	int r;

	if (req->len < sizeof(ipt_header)) {
		BFLOG_ERR("invalid request size: %d", req->len);
		return ERR_PTR(-EINVAL);
	}

	r = pvm_read(req->pid, &ipt_header, (const void *)req->addr,
		     sizeof(ipt_header));
	if (r) {
		BFLOG_ERR("failed to read from PID %d: %s", req->pid,
			  STRERR(r));
		return ERR_PTR(r);
	}

	if (ipt_header.num_counters == 0) {
		BFLOG_ERR("no counter defined in struct ipt_header");
		return ERR_PTR(-EINVAL);
	}

	if (ipt_header.num_counters >= INT_MAX / sizeof(struct bpfilter_ipt_counters)) {
		BFLOG_ERR("too many counters defined: %u",
			  ipt_header.num_counters);
		return ERR_PTR(-ENOMEM);
	}

	ipt_header.name[sizeof(ipt_header.name) - 1] = '\0';

	ipt_replace = malloc(sizeof(ipt_header) + ipt_header.size);
	if (!ipt_replace) {
		BFLOG_ERR("out of memory");
		return ERR_PTR(-ENOMEM);
	}

	memcpy(ipt_replace, &ipt_header, sizeof(ipt_header));

	r = pvm_read_from_offset(req->pid, ipt_replace, (const void *)req->addr,
				 sizeof(ipt_header), ipt_header.size);
	if (r) {
		free(ipt_replace);
		BFLOG_ERR("failed to read from PID %u at offset %lu: %s",
			  req->pid, sizeof(ipt_header), STRERR(r));
		return ERR_PTR(r);
	}

	return ipt_replace;
}

static int sockopt_set_replace(struct context *ctx,
			       const struct mbox_request *req)
{
	struct bpfilter_ipt_replace *ipt_replace;
	struct table *table;
	struct table *new_table = NULL;
	struct table_ops *table_ops;
	int r;

	ipt_replace = read_ipt_replace(ctx, req);
	if (IS_ERR(ipt_replace)) {
		BFLOG_ERR("failed to read struct ipt_replace: %s",
			  STRERR(PTR_ERR(ipt_replace)));
		return PTR_ERR(ipt_replace);
	}

	table_ops = map_find(&ctx->table_ops_map, ipt_replace->name);
	if (IS_ERR(table_ops)) {
		r = PTR_ERR(table_ops);
		BFLOG_ERR("cannot find table_ops '%s' in map", ipt_replace->name);
		goto cleanup;
	}

	new_table = table_ops->create(ctx, ipt_replace);
	if (IS_ERR(new_table)) {
		r = PTR_ERR(table_ops);
		BFLOG_ERR("failed to create table '%s'", ipt_replace->name);
		goto cleanup;
	}

	r = new_table->table_ops->codegen(ctx, new_table);
	if (r) {
		BFLOG_ERR("failed to generate code for table '%s'",
			  ipt_replace->name);
		goto cleanup;
	}

	table = map_find(&ctx->table_index.map, ipt_replace->name);
	if (IS_ERR(table) && PTR_ERR(table) == -ENOENT)
		table = NULL;

	if (IS_ERR(table)) {
		r = PTR_ERR(table);
		BFLOG_ERR("cannot find table '%s' in map", ipt_replace->name);
		goto cleanup;
	}

	if (table)
		table->table_ops->uninstall(ctx, table);

	r = new_table->table_ops->install(ctx, new_table);
	if (r) {
		BFLOG_ERR("failed to install new table '%s': %s",
			  ipt_replace->name, STRERR(r));
		if (table) {
			int r2 = table->table_ops->install(ctx, table);

			if (r2)
				BFLOG_EMERG("failed to restore old table '%s': %s",
					    table->table_ops->name,
					    STRERR(r2));
		}

		goto cleanup;
	}

	r = map_upsert(&ctx->table_index.map, new_table->table_ops->name,
		       new_table);
	if (r) {
		BFLOG_ERR("failed to upsert table map for '%s': %s",
			  new_table->table_ops->name, STRERR(r));
		goto cleanup;
	}

	list_add_tail(&new_table->list, &ctx->table_index.list);

	new_table = table;

cleanup:
	if (!IS_ERR_OR_NULL(new_table))
		new_table->table_ops->free(new_table);

	free(ipt_replace);

	return r;
}

static struct bpfilter_ipt_counters_info *read_ipt_counters_info(const struct mbox_request *req)
{
	struct bpfilter_ipt_counters_info *info;
	size_t size;
	int r;

	if (req->len < sizeof(*info)) {
		BFLOG_ERR("invalid request size: %d", req->len);
		return ERR_PTR(-EINVAL);
	}

	info = malloc(req->len);
	if (!info) {
		BFLOG_ERR("out of memory");
		return ERR_PTR(-ENOMEM);
	}

	r = pvm_read(req->pid, info, (const void *)req->addr, sizeof(*info));
	if (r) {
		BFLOG_ERR("failed to read from PID %d", req->pid);
		goto err_free;
	}

	size = info->num_counters * sizeof(info->counters[0]);
	if (req->len != sizeof(*info) + size) {
		BFLOG_ERR("not enough space to return counters");
		r = -EINVAL;
		goto err_free;
	}

	info->name[sizeof(info->name) - 1] = '\0';

	r = pvm_read_from_offset(req->pid, info, (const void *)req->addr,
				 sizeof(*info), size);
	if (r) {
		BFLOG_ERR("failed to read from PID %u at offset %lu: %s",
			  req->pid, sizeof(*info), STRERR(r));
		goto err_free;
	}

	return info;

err_free:
	free(info);

	return ERR_PTR(r);
}

static int sockopt_set_add_counters(struct context *ctx,
				    const struct mbox_request *req)
{
	struct bpfilter_ipt_counters_info *info;
	struct table *table;
	int r = 0;

	info = read_ipt_counters_info(req);
	if (IS_ERR(info)) {
		r = PTR_ERR(info);
		BFLOG_ERR("failed to read struct ipt_counters_info: %s",
			  STRERR(r));
		goto err_free;
	}

	table = map_find(&ctx->table_index.map, info->name);
	if (IS_ERR(table)) {
		r = PTR_ERR(table);
		BFLOG_ERR("cannot find table '%s' in map", info->name);
		goto err_free;
	}

	// TODO handle counters

err_free:
	free(info);

	return r;
}

static int handle_get_request(struct context *ctx,
			      const struct mbox_request *req)
{
	switch (req->cmd) {
	case 0:
		return 0;
	case BPFILTER_IPT_SO_GET_INFO:
		return sockopt_get_info(ctx, req);
	case BPFILTER_IPT_SO_GET_ENTRIES:
		return sockopt_get_entries(ctx, req);
	case BPFILTER_IPT_SO_GET_REVISION_MATCH:
		return sockopt_get_revision_match(ctx, req);
	case BPFILTER_IPT_SO_GET_REVISION_TARGET:
		return sockopt_get_revision_target(ctx, req);
	}

	BFLOG_ERR("unsupported SO_GET command: %d", req->cmd);
	return -ENOPROTOOPT;
}

static int handle_set_request(struct context *ctx,
			      const struct mbox_request *req)
{
	switch (req->cmd) {
	case BPFILTER_IPT_SO_SET_REPLACE:
		return sockopt_set_replace(ctx, req);
	case BPFILTER_IPT_SO_SET_ADD_COUNTERS:
		return sockopt_set_add_counters(ctx, req);
	}

	BFLOG_ERR("unsupported SO_SET command: %d", req->cmd);
	return -ENOPROTOOPT;
}

int handle_sockopt_request(struct context *ctx,
			   const struct mbox_request *req)
{
	return req->is_set ? handle_set_request(ctx, req) :
			     handle_get_request(ctx, req);
}
