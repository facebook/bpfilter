/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "table.h"

#include <errno.h>
#include <stdlib.h>

int bf_table_new(struct bf_table **table)
{
	struct bf_table *_table;

	_table = calloc(1, sizeof(*_table));
	if (!_table)
		return -ENOMEM;

	bf_list_init(&_table->chains);

	*table = _table;

	return 0;
}

void bf_table_free(struct bf_table **table)
{
	if (!*table)
		return;

	bf_list_foreach(&(*table)->chains, node) {
		struct bf_chain *chain = bf_list_node_data(node);
		bf_chain_free(&chain);
	}

	bf_list_clean(&(*table)->chains);

	free(*table);
	*table = NULL;
}
