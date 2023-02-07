// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#define _GNU_SOURCE

#include "match.h"

#include <linux/err.h>

#include <errno.h>
#include <string.h>

#include "context.h"
#include "logger.h"
#include "map-common.h"

int init_match(struct context *ctx, const struct bpfilter_ipt_match *ipt_match,
	       struct match *match)
{
	const size_t maxlen = sizeof(ipt_match->u.user.name);
	const struct match_ops *found;
	int r;

	if (strnlen(ipt_match->u.user.name, maxlen) == maxlen) {
		BFLOG_ERR("failed to init match: name too long");
		return -EINVAL;
	}

	found = map_find(&ctx->match_ops_map, ipt_match->u.user.name);
	if (IS_ERR(found)) {
		BFLOG_ERR("failed to find match by name: '%s'",
			  ipt_match->u.user.name);
		return PTR_ERR(found);
	}

	if (found->size + sizeof(*ipt_match) != ipt_match->u.match_size ||
	    found->revision != ipt_match->u.user.revision) {
		BFLOG_ERR("invalid match: '%s'", ipt_match->u.user.name);
		return -EINVAL;
	}

	r = found->check(ctx, ipt_match);
	if (r) {
		BFLOG_ERR("match check failed: %s", STRERR(r));
		return r;
	}

	match->match_ops = found;
	match->ipt_match = ipt_match;

	return 0;
}
