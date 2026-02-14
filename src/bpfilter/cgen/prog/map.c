// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/prog/map.h"

#include <linux/bpf.h>
#include <linux/btf.h>

#include <bpf/btf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/bpf_types.h>
#include <bpfilter/btf.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/logger.h>

#include "ctx.h"

static const char *_bf_map_type_strs[] = {
    [BF_MAP_TYPE_COUNTERS] = "BF_MAP_TYPE_COUNTERS",
    [BF_MAP_TYPE_PRINTER] = "BF_MAP_TYPE_PRINTER",
    [BF_MAP_TYPE_LOG] = "BF_MAP_TYPE_LOG",
    [BF_MAP_TYPE_SET] = "BF_MAP_TYPE_SET",
};
static_assert(ARRAY_SIZE(_bf_map_type_strs) == _BF_MAP_TYPE_MAX,
              "missing entries in _bf_map_type_strs array");

static const char *_bf_map_type_to_str(enum bf_map_type type)
{
    if (type < 0 || _BF_MAP_TYPE_MAX <= type)
        return NULL;

    return _bf_map_type_strs[type];
}

static int _bf_map_type_from_str(const char *str, enum bf_map_type *type)
{
    assert(type);

    for (enum bf_map_type i = 0; i < _BF_MAP_TYPE_MAX; ++i) {
        if (bf_streq(_bf_map_type_strs[i], str)) {
            *type = i;
            return 0;
        }
    }

    return -EINVAL;
}

#define _free_bf_btf_ __attribute__((__cleanup__(_bf_btf_free)))

static void _bf_btf_free(struct bf_btf **btf);

/**
 * @brief Create BTF data for a map.
 *
 * The BTF data is necessary to identify maps when creating a `bf_map` from
 * its file descriptor. While most types defined will help `bpftool` dumping
 * the map content and pretty-print it (e.g. counters map), the most important
 * part of the BTF data is the decl tag (`btf__add_decl_tag`), as it tags the
 * map's value for bpfilter to recognize it.
 *
 * BPF ring buffer maps do not support BTF data, so we will only rely on the
 * map type for now.
 *
 * @param btf BTF data to create. On success, `*btf` points to valid BTF data
 *        loaded into the kernel. Can't be NULL.
 * @param map Map associated to the BTF data. Can't be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_btf_new(struct bf_btf **btf, const struct bf_map *map)
{
    _free_bf_btf_ struct bf_btf *_btf = NULL;
    struct btf *raw;
    const void *data;
    uint32_t data_len;
    int r;

    assert(btf);
    assert(map);

    _btf = calloc(1, sizeof(struct bf_btf));
    if (!_btf)
        return -ENOMEM;

    _btf->fd = -1;

    _btf->btf = btf__new_empty();
    if (!_btf->btf)
        return bf_err_r(-errno, "failed to create BTF structure");

    raw = _btf->btf;

    /* It's not necessary to check the return value of each btf__xxx() call,
     * on error libbpf/kernel will refuse the BTF data. */
    switch (map->type) {
    case BF_MAP_TYPE_COUNTERS:
        _btf->key_type_id = btf__add_int(raw, "u32", 4, 0);

        _btf->value_type_id = btf__add_struct(raw, "bf_counters", 16);
        int counter_type_id = btf__add_int(raw, "u64", 8, 0);
        btf__add_field(raw, "packets", counter_type_id, 0, 0);
        btf__add_field(raw, "bytes", counter_type_id, 64, 0);
        break;
    case BF_MAP_TYPE_PRINTER:
        /* Printer maps are array maps: keys are an integer type, and values are
         * a placeholder struct. */
        _btf->key_type_id = btf__add_int(raw, "placeholder_key", 4, 0);
        _btf->value_type_id =
            btf__add_struct(raw, "placeholder_value", map->value_size);
        break;
    case BF_MAP_TYPE_SET:
        /* Set maps are hash maps: keys are a structure of fixed size, so are
         * values. */
        _btf->key_type_id =
            btf__add_struct(raw, "placeholder_key", map->key_size);
        _btf->value_type_id =
            btf__add_struct(raw, "placeholder_value", map->value_size);
        break;
    case BF_MAP_TYPE_LOG: /* BTF data on ring buffer maps is not supported */
    default:
        return bf_err_r(-ENOTSUP, "bf_map type %d is not supported", map->type);
    }

    r = btf__add_decl_tag(raw, _bf_map_type_to_str(map->type),
                          _btf->value_type_id, -1);
    if (r < 0)
        return bf_err_r(r, "failed to add decl tag to bf_map BTF data");

    data = btf__raw_data(raw, &data_len);
    if (!data)
        return bf_err_r(errno, "failed to request BTF raw data from libbpf");

    r = bf_bpf_btf_load(data, data_len, bf_ctx_token());
    if (r < 0)
        return bf_err_r(r, "failed to load BTF data for bf_map");

    _btf->fd = r;
    *btf = TAKE_PTR(_btf);

    return 0;
}

static void _bf_btf_free(struct bf_btf **btf)
{
    assert(btf);

    if (!*btf)
        return;

    btf__free((*btf)->btf);
    closep(&(*btf)->fd);
    freep((void *)btf);
}

static int _bf_map_new(struct bf_map **map, const char *name,
                       enum bf_map_type type, enum bf_bpf_map_type bpf_type,
                       size_t key_size, size_t value_size, size_t n_elems)
{
    _free_bf_map_ struct bf_map *_map = NULL;
    _free_bf_btf_ struct bf_btf *btf = NULL;
    _cleanup_close_ int fd = -1;
    int r;

    assert(map);
    assert(name);

    if (name[0] == '\0')
        return bf_err_r(-EINVAL, "bf_map %s: name can't be empty", name);

    if (type != BF_MAP_TYPE_LOG && key_size == 0)
        return bf_err_r(-EINVAL, "bf_map %s: key size can't be 0", name);
    if (type == BF_MAP_TYPE_LOG && key_size != 0)
        return bf_err_r(-EINVAL, "bf_map %s: key size must be", name);

    if (type != BF_MAP_TYPE_LOG && value_size == 0)
        return bf_err_r(-EINVAL, "bf_map %s: value size can't be 0", name);
    if (type == BF_MAP_TYPE_LOG && value_size != 0)
        return bf_err_r(-EINVAL, "bf_map %s: value size must be 0", name);

    if (n_elems == 0) {
        return bf_err_r(-EINVAL, "bf_map %s: number of elements can't be 0",
                        name);
    }

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    _map->type = type;
    _map->bpf_type = bpf_type;
    _map->key_size = key_size;
    _map->value_size = value_size;
    _map->n_elems = n_elems;
    _map->fd = -1;

    bf_strncpy(_map->name, BPF_OBJ_NAME_LEN, name);

    if (type != BF_MAP_TYPE_LOG) {
        r = _bf_btf_new(&btf, _map);
        if (r)
            return r;
    }

    r = bf_bpf_map_create(name, _map->bpf_type, _map->key_size,
                          _map->value_size, _map->n_elems, btf, bf_ctx_token());
    if (r < 0)
        return bf_err_r(r, "failed to create BPF map '%s'", name);

    _map->fd = r;
    *map = TAKE_PTR(_map);

    return 0;
}

int bf_map_new(struct bf_map **map, const char *name, enum bf_map_type type,
               size_t key_size, size_t value_size, size_t n_elems)
{
    static enum bf_bpf_map_type _map_type_to_bpf[_BF_MAP_TYPE_MAX] = {
        [BF_MAP_TYPE_COUNTERS] = BF_BPF_MAP_TYPE_ARRAY,
        [BF_MAP_TYPE_PRINTER] = BF_BPF_MAP_TYPE_ARRAY,
        [BF_MAP_TYPE_LOG] = BF_BPF_MAP_TYPE_RINGBUF,
    };

    assert(map);
    assert(name);

    if (type == BF_MAP_TYPE_SET) {
        return bf_err_r(
            -EINVAL,
            "use bf_map_new_from_set() to create a bf_map from a bf_set");
    }

    return _bf_map_new(map, name, type, _map_type_to_bpf[type], key_size,
                       value_size, n_elems);
}

int bf_map_new_from_set(struct bf_map **map, const char *name,
                        const struct bf_set *set)
{
    assert(map);
    assert(name);
    assert(set);

    return _bf_map_new(map, name, BF_MAP_TYPE_SET,
                       set->use_trie ? BF_BPF_MAP_TYPE_LPM_TRIE :
                                       BF_BPF_MAP_TYPE_HASH,
                       set->elem_size, 1, bf_list_size(&set->elems));
}

int bf_map_new_from_pack(struct bf_map **map, int dir_fd, bf_rpack_node_t node)
{
    _free_bf_map_ struct bf_map *_map = NULL;
    _cleanup_free_ char *name = NULL;
    int r;

    assert(map);

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    r = bf_rpack_kv_str(node, "name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_map.name");
    if (strlen(name) == 0)
        return bf_err_r(-EINVAL, "map name can't be empty");
    bf_strncpy(_map->name, BPF_OBJ_NAME_LEN, name);

    r = bf_rpack_kv_enum(node, "type", &_map->type, 0, _BF_MAP_TYPE_MAX);
    if (r)
        return bf_rpack_key_err(r, "bf_map.type");

    r = bf_rpack_kv_enum(node, "bpf_type", &_map->bpf_type, 0,
                         __MAX_BPF_MAP_TYPE);
    if (r)
        return bf_rpack_key_err(r, "bf_map.bpf_type");

    r = bf_rpack_kv_u64(node, "key_size", &_map->key_size);
    if (r)
        return bf_rpack_key_err(r, "bf_map.key_size");

    r = bf_rpack_kv_u64(node, "value_size", &_map->value_size);
    if (r)
        return bf_rpack_key_err(r, "bf_map.value_size");

    r = bf_rpack_kv_u64(node, "n_elems", &_map->n_elems);
    if (r)
        return bf_rpack_key_err(r, "bf_map.n_elems");
    if (_map->n_elems == 0)
        return bf_err_r(-EINVAL, "bf_map should not have 0 elements");

    r = bf_bpf_obj_get(_map->name, dir_fd, &_map->fd);
    if (r < 0) {
        return bf_err_r(r, "failed to open pinned BPF map '%s'", _map->name);
    }

    *map = TAKE_PTR(_map);

    return 0;
}

/**
 * @brief Get the `bf_map` type from a map's BTF data.
 *
 * Retrieve the BTF data associated with the given BTF ID, parse it,
 * and look for a `BTF_KIND_DECL_TAG` whose value matches a known
 * `bf_map_type` string.
 *
 * @param btf_id BTF ID associated with the map. Must be non-zero.
 * @param type On success, set to the corresponding `bf_map_type`. Can't
 *        be NULL.
 * @return 0 on success, or a negative errno value on failure.
 */
static int _bf_map_type_from_btf(uint32_t btf_id, enum bf_map_type *type)
{
    _cleanup_close_ int btf_fd = -1;
    _cleanup_free_ void *data = NULL;
    struct bpf_btf_info btf_info = {};
    struct btf *btf;
    int r;

    assert(btf_id);
    assert(type);

    btf_fd = bf_bpf_btf_get_fd_by_id(btf_id);
    if (btf_fd < 0)
        return bf_err_r(btf_fd, "failed to get BTF fd for ID %u", btf_id);

    r = bf_bpf_obj_get_info(btf_fd, &btf_info, sizeof(btf_info));
    if (r)
        return bf_err_r(r, "failed to query BTF info size for ID %u", btf_id);

    if (btf_info.btf_size == 0)
        return bf_err_r(-ENODATA, "BTF data is empty for ID %u", btf_id);

    data = malloc(btf_info.btf_size);
    if (!data)
        return -ENOMEM;

    btf_info.btf = bf_ptr_to_u64(data);

    r = bf_bpf_obj_get_info(btf_fd, &btf_info, sizeof(btf_info));
    if (r)
        return bf_err_r(r, "failed to retrieve BTF data for ID %u", btf_id);

    btf = btf__new(data, btf_info.btf_size);
    if (!btf)
        return bf_err_r(-errno, "failed to parse BTF data for ID %u", btf_id);

    for (uint32_t i = 1; i < btf__type_cnt(btf); ++i) {
        const struct btf_type *btf_type = btf__type_by_id(btf, i);

        if (BTF_INFO_KIND(btf_type->info) != BTF_KIND_DECL_TAG)
            continue;

        r = _bf_map_type_from_str(btf__name_by_offset(btf, btf_type->name_off),
                                  type);
        if (r == 0) {
            btf__free(btf);
            return 0;
        }
    }

    btf__free(btf);

    return bf_err_r(
        -ENOENT, "no bf_map type decl tag found in BTF data for ID %u", btf_id);
}

int bf_map_new_from_fd(struct bf_map **map, int fd)
{
    _free_bf_map_ struct bf_map *_map = NULL;
    struct bpf_map_info info = {};
    int r;

    assert(map);

    r = bf_bpf_obj_get_info(fd, &info, sizeof(info));
    if (r)
        return bf_err_r(r, "failed to get BPF map info from fd %d", fd);

    _map = malloc(sizeof(*_map));
    if (!_map)
        return -ENOMEM;

    bf_strncpy(_map->name, BPF_OBJ_NAME_LEN, info.name);
    _map->bpf_type = info.type;
    _map->key_size = info.key_size;
    _map->value_size = info.value_size;
    _map->n_elems = info.max_entries;

    _map->fd = dup(fd);
    if (_map->fd < 0)
        return bf_err_r(-errno, "failed to duplicate map fd %d", fd);

    if (info.btf_id) {
        r = _bf_map_type_from_btf(info.btf_id, &_map->type);
        if (r)
            return r;
    } else if (info.type == BF_BPF_MAP_TYPE_RINGBUF) {
        _map->type = BF_MAP_TYPE_LOG;
    } else {
        return bf_err_r(
            -ENOTSUP,
            "BPF map '%s' has no BTF data, can't determine bf_map type",
            info.name);
    }

    *map = TAKE_PTR(_map);

    return 0;
}

void bf_map_free(struct bf_map **map)
{
    assert(map);

    if (!*map)
        return;

    closep(&(*map)->fd);
    freep((void *)map);
}

int bf_map_pack(const struct bf_map *map, bf_wpack_t *pack)
{
    assert(map);
    assert(pack);

    bf_wpack_kv_str(pack, "name", map->name);
    bf_wpack_kv_enum(pack, "type", map->type);
    bf_wpack_kv_enum(pack, "bpf_type", map->bpf_type);
    bf_wpack_kv_u64(pack, "key_size", map->key_size);
    bf_wpack_kv_u64(pack, "value_size", map->value_size);
    bf_wpack_kv_u64(pack, "n_elems", map->n_elems);

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

static const char *_bf_bpf_type_to_str(enum bf_bpf_map_type type)
{
    static const char *type_strs[] = {
        [BF_BPF_MAP_TYPE_HASH] = "BF_BPF_MAP_TYPE_HASH",
        [BF_BPF_MAP_TYPE_ARRAY] = "BF_BPF_MAP_TYPE_ARRAY",
        [BF_BPF_MAP_TYPE_LPM_TRIE] = "BF_BPF_MAP_TYPE_LPM_TRIE",
        [BF_BPF_MAP_TYPE_RINGBUF] = "BF_BPF_MAP_TYPE_RINGBUF",
    };

    return type_strs[type] ? type_strs[type] : "<no mapping>";
}

void bf_map_dump(const struct bf_map *map, prefix_t *prefix)
{
    assert(map);
    assert(prefix);

    DUMP(prefix, "struct bf_map at %p", map);

    bf_dump_prefix_push(prefix);
    DUMP(prefix, "type: %s", _bf_map_type_to_str(map->type));
    DUMP(prefix, "name: %s", map->name);
    DUMP(prefix, "bpf_type: %s", _bf_bpf_type_to_str(map->bpf_type));
    DUMP(prefix, "key_size: %lu", map->key_size);
    DUMP(prefix, "value_size: %lu", map->value_size);

    bf_dump_prefix_last(prefix);
    DUMP(prefix, "fd: %d", map->fd);

    bf_dump_prefix_pop(prefix);
}

int bf_map_pin(const struct bf_map *map, int dir_fd)
{
    int r;

    assert(map);

    r = bf_bpf_obj_pin(map->name, map->fd, dir_fd);
    if (r < 0)
        return bf_err_r(r, "failed to pin BPF map '%s'", map->name);

    return 0;
}

void bf_map_unpin(const struct bf_map *map, int dir_fd)
{
    int r;

    assert(map);

    r = unlinkat(dir_fd, map->name, 0);
    if (r < 0 && errno != ENOENT) {
        // Do not warn on ENOENT, we want the file to be gone!
        bf_warn_r(
            errno,
            "failed to unlink BPF map '%s', assuming the map is not pinned",
            map->name);
    }
}

int bf_map_set_elem(const struct bf_map *map, void *key, void *value)
{
    assert(map);
    assert(key);
    assert(value);

    return bf_bpf_map_update_elem(map->fd, key, value, 0);
}
