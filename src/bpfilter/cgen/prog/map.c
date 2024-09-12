// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/map.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/dump.h"
#include "core/helper.h"
#include "core/logger.h"
#include "core/marsh.h"

int bf_bpf_map_new(struct bf_bpf_map **map, const char *name_suffix,
                   enum bf_bpf_map_type type, size_t key_size,
                   size_t value_size, size_t n_elems)
{
    _cleanup_bf_bpf_map_ struct bf_bpf_map *_map = NULL;
    int r;

    bf_assert(map);
    bf_assert(name_suffix);
    bf_assert(key_size > 0);
    bf_assert(n_elems > 0);

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->fd = -1;
    _map->type = type;
    _map->key_size = key_size;
    _map->value_size = value_size;
    _map->n_elems = n_elems;

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

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_map->type, elem->data, sizeof(_map->type));

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_map->key_size, elem->data, sizeof(_map->key_size));

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_map->value_size, elem->data, sizeof(_map->value_size));

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_map->n_elems, elem->data, sizeof(_map->n_elems));

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

    r = bf_marsh_add_child_raw(&_marsh, &map->type, sizeof(map->type));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &map->key_size, sizeof(map->key_size));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &map->value_size,
                               sizeof(map->value_size));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &map->n_elems, sizeof(map->n_elems));
    if (r < 0)
        return r;

    *marsh = TAKE_PTR(_marsh);

    return 0;
}

void bf_bpf_map_dump(const struct bf_bpf_map *map, prefix_t *prefix)
{
    bf_assert(map);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_bpf_map at %p", map);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "fd: %d", map->fd);
    DUMP(prefix, "name: %s", map->name);
    DUMP(prefix, "path: %s", map->path);
    DUMP(prefix, "type: %s", bf_bpf_map_type_to_str(map->type));
    DUMP(prefix, "key_size: %lu", map->key_size);
    DUMP(prefix, "value_size: %lu", map->value_size);
    DUMP(bf_dump_prefix_last(prefix), "n_elems: %lu", map->n_elems);
    bf_dump_prefix_pop(prefix);
}

static enum bpf_map_type
_bf_bpf_map_type_to_kernel_type(enum bf_bpf_map_type type)
{
    static const enum bpf_map_type _types[] = {
        [BF_BPF_MAP_TYPE_ARRAY] = BPF_MAP_TYPE_ARRAY,
        [BF_BPF_MAP_TYPE_HASH] = BPF_MAP_TYPE_HASH,
    };

    bf_assert(0 <= type && type < _BF_BPF_MAP_TYPE_MAX);

    return _types[type];
}

int bf_bpf_map_create(struct bf_bpf_map *map, uint32_t flags, bool pin)
{
    union bpf_attr attr = {};
    _cleanup_close_ int fd = -1;
    int r;

    bf_assert(map);

    attr.map_type = _bf_bpf_map_type_to_kernel_type(map->type);
    attr.key_size = map->key_size;
    attr.value_size = map->value_size;
    attr.max_entries = map->n_elems;
    attr.map_flags = flags;

    (void)snprintf(attr.map_name, BPF_OBJ_NAME_LEN, "%s", map->name);

    r = bf_bpf(BPF_MAP_CREATE, &attr);
    if (r < 0)
        return bf_err_r(r, "failed to create BPF map '%s'", map->name);

    fd = r;
    if (pin) {
        r = bf_bpf_obj_pin(map->path, fd);
        if (r < 0)
            return bf_err_r(r, "failed to pin BPF map to '%s'", map->path);
    }

    map->fd = TAKE_FD(fd);

    return 0;
}

void bf_bpf_map_destroy(struct bf_bpf_map *map, bool unpin)
{
    bf_assert(map);

    closep(&map->fd);

    if (unpin && unlink(map->path) < 0) {
        bf_warn_r(
            errno,
            "failed to unlink BPF map '%s', assuming the map is destroyed",
            map->path);
    }
}

static const char *_bf_bpf_map_type_strs[] = {
    [BF_BPF_MAP_TYPE_ARRAY] = "BF_BPF_MAP_TYPE_ARRAY",
    [BF_BPF_MAP_TYPE_HASH] = "BF_BPF_MAP_TYPE_HASH",
};

static_assert(ARRAY_SIZE(_bf_bpf_map_type_strs) == _BF_BPF_MAP_TYPE_MAX,
              "missing entries in _bf_bpf_map_type_strs array");

const char *bf_bpf_map_type_to_str(enum bf_bpf_map_type type)
{
    bf_assert(0 <= type && type < _BF_BPF_MAP_TYPE_MAX);

    return _bf_bpf_map_type_strs[type];
}

int bf_bpf_map_type_from_str(const char *str, enum bf_bpf_map_type *type)
{
    bf_assert(str);
    bf_assert(type);

    for (size_t i = 0; i < _BF_BPF_MAP_TYPE_MAX; ++i) {
        if (bf_streq(_bf_bpf_map_type_strs[i], str)) {
            *type = i;
            return 0;
        }
    }

    return -EINVAL;
}
