// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "map.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

int bf_map_new(bf_map **map, size_t nelem)
{
    bf_map *_map;

    assert(map);

    _map = calloc(1, sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    if (!hcreate_r(nelem, &_map->data)) {
        free(_map);
        return -errno;
    }

    *map = _map;

    return 0;
}

void bf_map_free(bf_map **map)
{
    hdestroy_r(&(*map)->data);
    free(*map);
    *map = NULL;
}

int bf_map_find(bf_map *map, const char *key, void **value)
{
    const ENTRY needle = {.key = (char *)key};
    ENTRY *found;

    assert(map);
    assert(key);
    assert(value);

    if (!hsearch_r(needle, FIND, &found, &map->data))
        return -ENOENT;

    *value = found->data;

    return 0;
}

int bf_map_upsert(bf_map *map, const char *key, void *value)
{
    const ENTRY needle = {.key = (char *)key, .data = value};
    ENTRY *found;

    assert(map);
    assert(key);
    assert(value);

    if (!hsearch_r(needle, ENTER, &found, &map->data))
        return -errno;

    found->key = (char *)key;
    found->data = value;

    return 0;
}
