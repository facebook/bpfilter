/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "chain.h"

#include <errno.h>
#include <stdlib.h>

int bf_rule_new(struct bf_rule **rule)
{
	struct bf_rule *_rule;

	_rule = calloc(1, sizeof(*_rule));
	if (!_rule)
		return -ENOMEM;

	bf_list_init(&_rule->matches);

	*rule = _rule;

	return 0;
}

void bf_rule_free(struct bf_rule **rule)
{
	if (!*rule)
		return;

	bf_list_foreach(&(*rule)->matches, node) {
        struct bf_match *match = bf_list_node_get_data(node);
		bf_match_free(&match);
	}

	bf_list_clean(&(*rule)->matches);

	bf_target_free(&(*rule)->target);

	free(*rule);
	*rule = NULL;
}
