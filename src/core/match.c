/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "match.h"

#include <errno.h>
#include <stdlib.h>

int bf_match_new(struct bf_match **match)
{
	struct bf_match *_match;

	_match = calloc(1, sizeof(*_match));
	if (!_match)
		return -ENOMEM;

	*match = _match;

	return 0;
}

void bf_match_free(struct bf_match **match)
{
	if (!*match)
		return;

	free(*match);
	*match = NULL;
}
