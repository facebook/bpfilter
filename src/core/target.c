/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "target.h"

#include <errno.h>
#include <stdlib.h>

int bf_target_new(struct bf_target **target)
{
	struct bf_target *_target;

	_target = calloc(1, sizeof(*_target));
	if (!_target)
		return -ENOMEM;

	*target = _target;

	return 0;
}

void bf_target_free(struct bf_target **target)
{
	if (!*target)
		return;

	free(*target);
	*target = NULL;
}
