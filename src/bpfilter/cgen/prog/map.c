// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "bpfilter/cgen/prog/map.h"

#include <linux/bpf.h>

#include <bpf/btf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/bpf.h"
#include "core/dump.h"
#include "core/helper.h"
#include "core/io.h"
#include "core/logger.h"
#include "core/marsh.h"

static const char _bf_map_type_key[] = {
    [BF_MAP_TYPE_COUNTERS] = 'c',
    [BF_MAP_TYPE_PRINTER] = 'p',
    [BF_MAP_TYPE_SET] = 's',
};

int bf_map_new(struct bf_map **map, enum bf_map_type type,
               const char *name_suffix, enum bf_map_bpf_type bpf_type,
               size_t key_size, size_t value_size, size_t n_elems)
{
    _cleanup_bf_map_ struct bf_map *_map = NULL;
    int r;

    bf_assert(map);
    bf_assert(name_suffix);
    bf_assert(key_size > 0 && value_size > 0 && n_elems > 0);

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->type = type;
    _map->fd = -1;
    _map->bpf_type = bpf_type;
    _map->key_size = key_size;
    _map->value_size = value_size;
    _map->n_elems = n_elems;

    r = snprintf(_map->name, BPF_OBJ_NAME_LEN, "bf_%cmap_%.6s",
                 _bf_map_type_key[type], name_suffix);
    if (r < 0) {
        return bf_err_r(
            errno,
            "failed to write map name to bf_map object using suffix '%s'",
            name_suffix);
    }

    r = snprintf(_map->path, BF_PIN_PATH_LEN, "%s/%s", BF_PIN_DIR, _map->name);
    if (r < 0) {
        return bf_err_r(
            errno,
            "failed to write map pin path to bf_map object using map name '%s'",
            _map->name);
    }
    if (BF_PIN_PATH_LEN <= (unsigned int)r) {
        bf_err(
            "failed to write map pin path to bf_map object: map name '%s' is too long",
            _map->name);
        return -E2BIG;
    }

    *map = TAKE_PTR(_map);

    return 0;
}

int bf_map_new_from_marsh(struct bf_map **map, const struct bf_marsh *marsh)
{
    _cleanup_bf_map_ struct bf_map *_map = NULL;
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
    memcpy(&_map->type, elem->data, sizeof(_map->type));

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(_map->name, elem->data, BPF_OBJ_NAME_LEN);

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(_map->path, elem->data, BF_PIN_PATH_LEN);

    if (!(elem = bf_marsh_next_child(marsh, elem)))
        return -EINVAL;
    memcpy(&_map->bpf_type, elem->data, sizeof(_map->bpf_type));

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
        return bf_err_r(-E2BIG, "too many elements in bf_map marsh");

    r = bf_bpf_obj_get(_map->path, &_map->fd);
    if (r < 0)
        return bf_err_r(r, "failed to open pinned BPF map '%s'", _map->path);

    *map = TAKE_PTR(_map);

    return 0;
}

void bf_map_free(struct bf_map **map)
{
    bf_assert(map);

    if (!*map)
        return;

    closep(&(*map)->fd);
    freep((void *)map);
}

int bf_map_marsh(const struct bf_map *map, struct bf_marsh **marsh)
{
    _cleanup_bf_marsh_ struct bf_marsh *_marsh = NULL;
    int r;

    bf_assert(map);
    bf_assert(marsh);

    r = bf_marsh_new(&_marsh, NULL, 0);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &map->type, sizeof(map->type));
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, map->name, BPF_OBJ_NAME_LEN);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, map->path, BF_PIN_PATH_LEN);
    if (r < 0)
        return r;

    r = bf_marsh_add_child_raw(&_marsh, &map->bpf_type, sizeof(map->bpf_type));
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

static const char *_bf_map_type_to_str(enum bf_map_type type)
{
    static const char *type_strs[] = {
        [BF_MAP_TYPE_COUNTERS] = "BF_MAP_TYPE_COUNTERS",
        [BF_MAP_TYPE_PRINTER] = "BF_MAP_TYPE_PRINTER",
        [BF_MAP_TYPE_SET] = "BF_MAP_TYPE_SET",
    };

    static_assert(ARRAY_SIZE(type_strs) == _BF_MAP_TYPE_MAX,
                  "missing entries in _bf_map_type_strs array");
    bf_assert(0 <= type && type < _BF_MAP_TYPE_MAX);

    return type_strs[type];
}

void bf_map_dump(const struct bf_map *map, prefix_t *prefix)
{
    bf_assert(map);
    bf_assert(prefix);

    DUMP(prefix, "struct bf_map at %p", map);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "type: %s", _bf_map_type_to_str(map->type));
    DUMP(prefix, "fd: %d", map->fd);
    DUMP(prefix, "name: %s", map->name);
    DUMP(prefix, "path: %s", map->path);
    DUMP(prefix, "bpf_type: %s", bf_map_bpf_type_to_str(map->bpf_type));
    DUMP(prefix, "key_size: %lu", map->key_size);
    DUMP(prefix, "value_size: %lu", map->value_size);

    bf_dump_prefix_last(prefix);
    if (map->n_elems == BF_MAP_N_ELEMS_UNKNOWN) {
        DUMP(prefix, "n_elems: unknown");
    } else {
        DUMP(prefix, "n_elems: %lu", map->n_elems);
    }

    bf_dump_prefix_pop(prefix);
}

static enum bpf_map_type
_bf_map_bpf_type_to_kernel_type(enum bf_map_bpf_type bpf_type)
{
    static const enum bpf_map_type _kernel_types[] = {
        [BF_MAP_BPF_TYPE_ARRAY] = BPF_MAP_TYPE_ARRAY,
        [BF_MAP_BPF_TYPE_HASH] = BPF_MAP_TYPE_HASH,
    };

    bf_assert(0 <= bpf_type && bpf_type < _BF_MAP_BPF_TYPE_MAX);

    return _kernel_types[bpf_type];
}

#define _cleanup_bf_btf_ __attribute__((__cleanup__(_bf_btf_free)))

struct bf_btf
{
    struct btf *btf;
    uint32_t key_type_id;
    uint32_t value_type_id;
};

static void _bf_btf_free(struct bf_btf **btf);

static int _bf_btf_new(struct bf_btf **btf)
{
    _cleanup_bf_btf_ struct bf_btf *_btf = NULL;

    bf_assert(btf);

    _btf = malloc(sizeof(struct bf_btf));
    if (!_btf)
        return -ENOMEM;

    _btf->btf = btf__new_empty();
    if (!_btf->btf)
        return -errno;

    *btf = TAKE_PTR(_btf);

    return 0;
}

static void _bf_btf_free(struct bf_btf **btf)
{
    bf_assert(btf);

    if (!*btf)
        return;

    btf__free((*btf)->btf);
    freep((void *)btf);
}

/**
 * Create the BTF data for the map.
 *
 * @param map Map to create the BTF data for. @c map.type will define the
 *        exact content of the BTF object. Can't be NULL.
 * @return A @ref bf_btf structure on success, or NULL on error. The
 *         @ref bf_btf structure is owned by the caller.
 */
static struct bf_btf *_bf_map_make_btf(const struct bf_map *map)
{
    _cleanup_bf_btf_ struct bf_btf *btf = NULL;
    struct btf *kbtf;
    int r;

    bf_assert(map);

    r = _bf_btf_new(&btf);
    if (r < 0)
        return NULL;

    kbtf = btf->btf;

    switch (map->type) {
    case BF_MAP_TYPE_COUNTERS:
        btf__add_int(kbtf, "u64", 8, 0);
        btf->key_type_id = btf__add_int(kbtf, "u32", 4, 0);
        btf->value_type_id = btf__add_struct(kbtf, "bf_counters", 16);
        btf__add_field(kbtf, "packets", 1, 0, 0);
        btf__add_field(kbtf, "bytes", 1, 64, 0);
        break;
    case BF_MAP_TYPE_PRINTER:
    case BF_MAP_TYPE_SET:
        bf_warn("bf_map type %s is not yet supported",
                _bf_map_type_to_str(map->type));
        return NULL;
    default:
        bf_err_r(-ENOTSUP, "bf_map type %d is not supported", map->type);
        return NULL;
    }

    r = btf__load_into_kernel(kbtf);
    if (r < 0) {
        bf_err_r(r, "failed to load BPF map BTF data into kernel");
        return NULL;
    }

    return TAKE_PTR(btf);
}

int bf_map_create(struct bf_map *map, uint32_t flags)
{
    union bpf_attr attr = {};
    _cleanup_bf_btf_ struct bf_btf *btf = NULL;
    int r;

    bf_assert(map);

    if (map->n_elems == BF_MAP_N_ELEMS_UNKNOWN) {
        return bf_err_r(
            -EINVAL,
            "can't create a map with BF_MAP_N_ELEMS_UNKNOWN number of elements");
    }

    attr.map_type = _bf_map_bpf_type_to_kernel_type(map->bpf_type);
    attr.key_size = map->key_size;
    attr.value_size = map->value_size;
    attr.max_entries = map->n_elems;
    attr.map_flags = flags;

    /** The BTF data is not mandatory to use the map, but a good addition.
     * Hence, bpfilter will try to make the BTF data available, but will
     * ignore if that fails. @ref _bf_map_make_btf is used to isolate the
     * BTF data generation: if it fails we ignore the issue, but if it
     * succeeds we update the @c bpf_attr structure with the BTF details.
     * There is some boilerplate for @ref bf_btf structure, it could be
     * simpler, but the current implementation ensure the BTF data is properly
     * freed on error, without preventing the BPF map to be created. */
    btf = _bf_map_make_btf(map);
    if (btf) {
        attr.btf_fd = btf__fd(btf->btf);
        attr.btf_key_type_id = btf->key_type_id;
        attr.btf_value_type_id = btf->value_type_id;
    }

    (void)snprintf(attr.map_name, BPF_OBJ_NAME_LEN, "%s", map->name);

    r = bf_bpf(BPF_MAP_CREATE, &attr);
    if (r < 0)
        return bf_err_r(r, "failed to create BPF map '%s'", map->name);

    map->fd = r;

    return 0;
}

void bf_map_destroy(struct bf_map *map)
{
    bf_assert(map);

    closep(&map->fd);
}

int bf_map_pin(const struct bf_map *map)
{
    int r;

    bf_assert(map);

    r = bf_bpf_obj_pin(map->path, map->fd);
    if (r < 0)
        return bf_err_r(r, "failed to pin BPF map to '%s'", map->path);

    return 0;
}

void bf_map_unpin(const struct bf_map *map)
{
    bf_assert(map);

    if (unlink(map->path) < 0) {
        bf_warn_r(
            errno,
            "failed to unlink BPF map '%s', assuming the map is destroyed",
            map->path);
    }
}

int bf_map_set_n_elems(struct bf_map *map, size_t n_elems)
{
    bf_assert(n_elems != 0);

    if (map->fd != -1) {
        return bf_err_r(
            -EPERM,
            "can't change the number of elements in a map once the map has been created");
    }

    map->n_elems = n_elems;

    return 0;
}

int bf_map_set_elem(const struct bf_map *map, void *key, void *value)
{
    union bpf_attr attr = {};

    bf_assert(map && key && value);

    attr.map_fd = map->fd;
    attr.key = (unsigned long long)key;
    attr.value = (unsigned long long)value;
    attr.flags = BPF_ANY;

    return bf_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static const char *_bf_map_bpf_type_strs[] = {
    [BF_MAP_BPF_TYPE_ARRAY] = "BF_MAP_BPF_TYPE_ARRAY",
    [BF_MAP_BPF_TYPE_HASH] = "BF_MAP_BPF_TYPE_HASH",
};

static_assert(ARRAY_SIZE(_bf_map_bpf_type_strs) == _BF_MAP_BPF_TYPE_MAX,
              "missing entries in _bf_map_bpf_type_strs array");

const char *bf_map_bpf_type_to_str(enum bf_map_bpf_type bpf_type)
{
    bf_assert(0 <= bpf_type && bpf_type < _BF_MAP_BPF_TYPE_MAX);

    return _bf_map_bpf_type_strs[bpf_type];
}

int bf_map_bpf_type_from_str(const char *str, enum bf_map_bpf_type *bpf_type)
{
    bf_assert(str);
    bf_assert(bpf_type);

    for (size_t i = 0; i < _BF_MAP_BPF_TYPE_MAX; ++i) {
        if (bf_streq(_bf_map_bpf_type_strs[i], str)) {
            *bpf_type = i;
            return 0;
        }
    }

    return -EINVAL;
}
