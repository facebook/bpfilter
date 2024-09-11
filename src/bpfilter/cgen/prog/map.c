// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/map.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/bpf.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"

int bf_bpf_map_new(struct bf_bpf_map **map, const char *name_suffix)
{
    _cleanup_bf_bpf_map_ struct bf_bpf_map *_map = NULL;
    int r;

    bf_assert(map);
    bf_assert(name_suffix);

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->fd = -1;

    r = snprintf(_map->name, BPF_OBJ_NAME_LEN, "bf_map_%.6s", name_suffix);
    if (r < 0) {
        return bf_err_r(
            errno,
            "failed to write map name to bf_bpf_map object using suffix '%s'",
            name_suffix);
    }

    r = snprintf(_map->path, BF_PIN_PATH_LEN, "/sys/fs/bpf/%s", _map->name);
    if (r < 0) {
        return bf_err_r(
            errno,
            "failed to write map pin path to bf_bpf_map object using map name '%s'",
            _map->name);
    }
    if (BF_PIN_PATH_LEN <= (unsigned int)r) {
        bf_err(
            "failed to write map pin path to bf_bpf_map object: map name '%s' is too long",
            _map->name);
        return -E2BIG;
    }

    *map = TAKE_PTR(_map);

    return 0;
}

int bf_bpf_map_new_from_marsh(struct bf_bpf_map **map,
                              const struct bf_marsh *marsh)
{
    _cleanup_bf_bpf_map_ struct bf_bpf_map *_map = NULL;
    struct bf_marsh *elem = NULL;
    int r;

    bf_assert(map);
    bf_assert(marsh);

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->fd = -1;

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(_map->name, elem->data, BPF_OBJ_NAME_LEN);

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(_map->path, elem->data, BF_PIN_PATH_LEN);

    if (bf_marsh_next_child(marsh, elem))
        return bf_err_r(-E2BIG, "too many elements in bf_bpf_map marsh");

    r = bf_bpf_obj_get(_map->path, &_map->fd);
    if (r < 0)
        return bf_err_r(r, "failed to open pinned BPF map '%s'", _map->path);

    *map = TAKE_PTR(_map);

    return 0;
}

void bf_bpf_map_free(struct bf_bpf_map **map)
{
    bf_assert(map);

    if (!*map)
        return;

    closep(&(*map)->fd);
    freep((void *)map);
}

int bf_bpf_map_marsh(const struct bf_bpf_map *map, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(map);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, map->name, BPF_OBJ_NAME_LEN);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, map->path, BF_PIN_PATH_LEN);
    if (r < 0)
        return r;

    *marsh = TAKE_PTR(_marsh);

    return 0;
}
