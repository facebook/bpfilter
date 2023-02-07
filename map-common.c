// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Telegram FZ-LLC
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "map-common.h"

#include <linux/err.h>

#include <errno.h>
#include <string.h>

int create_map(struct hsearch_data *htab, size_t nelem)
{
	memset(htab, 0, sizeof(*htab));
	if (!hcreate_r(nelem, htab))
		return -errno;

	return 0;
}

void *map_find(struct hsearch_data *htab, const char *key)
{
	const ENTRY needle = { .key = (char *)key };
	ENTRY *found;

	if (!hsearch_r(needle, FIND, &found, htab))
		return ERR_PTR(-ENOENT);

	return found->data;
}

int map_upsert(struct hsearch_data *htab, const char *key, void *value)
{
	const ENTRY needle = { .key = (char *)key, .data = value };
	ENTRY *found;

	if (!hsearch_r(needle, ENTER, &found, htab))
		return -errno;

	found->key = (char *)key;
	found->data = value;

	return 0;
}

void free_map(struct hsearch_data *htab)
{
	hdestroy_r(htab);
}
