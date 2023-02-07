// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "context.h"
#include "filter-table.h"
#include "logger.h"
#include "msgfmt.h"
#include "sockopt.h"

#define do_exact(fd, op, buffer, count)							  \
	({										  \
		typeof(count) __count = count;						  \
		size_t total = 0;							  \
		int r = 0;								  \
											  \
		do {									  \
			const ssize_t part = op(fd, (buffer) + total, (__count) - total); \
			if (part > 0) {							  \
				total += part;						  \
			} else if (part == 0 && (__count) > 0) {			  \
				r = -EIO;						  \
				break;							  \
			} else if (part == -1) {					  \
				if (errno == EINTR)					  \
					continue;					  \
				r = -errno;						  \
				break;							  \
			}								  \
		} while (total < (__count));						  \
											  \
		r;									  \
	})

static int read_exact(int fd, void *buffer, size_t count)
{
	return do_exact(fd, read, buffer, count);
}

static int write_exact(int fd, const void *buffer, size_t count)
{
	return do_exact(fd, write, buffer, count);
}

static int setup_context(struct context *ctx)
{
	int r;

	r = logger_init();
	if (r < 0)
		return r;

	BFLOG_DBG("log file opened and ready to use");

	r = create_filter_table(ctx);
	if (r < 0)
		BFLOG_ERR("failed to created filter table: %s", STRERR(r));

	return r;
}

static void loop(struct context *ctx)
{
	struct mbox_request req;
	struct mbox_reply reply;
	int r;

	for (;;) {
		r = read_exact(STDIN_FILENO, &req, sizeof(req));
		if (r)
			BFLOG_EMERG("cannot read request: %s", STRERR(r));

		reply.status = handle_sockopt_request(ctx, &req);

		r = write_exact(STDOUT_FILENO, &reply, sizeof(reply));
		if (r)
			BFLOG_EMERG("cannot write reply: %s", STRERR(r));
	}
}

int main(void)
{
	struct context ctx;
	int r;

	r = create_context(&ctx);
	if (r)
		return r;

	r = setup_context(&ctx);
	if (r) {
		free_context(&ctx);
		return r;
	}

	loop(&ctx);

	// Disregard return value, the application is closed anyway.
	(void)logger_clean();

	return 0;
}
