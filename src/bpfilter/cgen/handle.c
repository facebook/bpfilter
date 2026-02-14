/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2023 Meta Platforms, Inc. and affiliates.
 */

#include "cgen/handle.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpfilter/bpf.h>
#include <bpfilter/counter.h>
#include <bpfilter/dump.h>
#include <bpfilter/helper.h>
#include <bpfilter/hook.h>
#include <bpfilter/list.h>
#include <bpfilter/logger.h>
#include <bpfilter/pack.h>

#include "cgen/prog/link.h"
#include "cgen/prog/map.h"
#include "ctx.h"

int bf_handle_new(struct bf_handle **handle, const char *prog_name)
{
    _free_bf_handle_ struct bf_handle *_handle = NULL;

    assert(handle);
    assert(prog_name);

    _handle = calloc(1, sizeof(*_handle));
    if (!_handle)
        return -ENOMEM;

    (void)snprintf(_handle->prog_name, BPF_OBJ_NAME_LEN, "%s", prog_name);
    _handle->prog_fd = -1;
    _handle->sets = bf_list_default(bf_map_free, bf_map_pack);

    *handle = TAKE_PTR(_handle);

    return 0;
}

int bf_handle_new_from_pack(struct bf_handle **handle, int dir_fd,
                            bf_rpack_node_t node)
{
    _free_bf_hookopts_ struct bf_hookopts *hookopts = NULL;
    _free_bf_handle_ struct bf_handle *_handle = NULL;
    _cleanup_free_ uint32_t *map_ids = NULL;
    _cleanup_close_ int link_fd = -1;
    _cleanup_close_ int link_extra_fd = -1;
    _cleanup_free_ char *name = NULL;
    struct bpf_prog_info prog_info = {};
    bf_rpack_node_t child;
    int r;

    assert(handle);

    r = bf_rpack_kv_str(node, "prog_name", &name);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.name");

    r = bf_handle_new(&_handle, name);
    if (r)
        return r;

    r = bf_bpf_obj_get(_handle->prog_name, dir_fd, &_handle->prog_fd);
    if (r < 0)
        return bf_err_r(r, "failed to restore bf_handle.prog_fd from pin");

    r = bf_rpack_kv_node(node, "hookopts", &child);
    if (r)
        return bf_rpack_key_err(r, "bf_handle.hookopts");
    if (!bf_rpack_is_nil(child)) {
        r = bf_hookopts_new_from_pack(&hookopts, child);
        if (r)
            return bf_rpack_key_err(r, "bf_handle.hookopts");

        r = bf_bpf_obj_get("bf_link", dir_fd, &link_fd);
        if (r)
            return bf_err_r(r, "failed to open chain's link");

        r = bf_bpf_obj_get("bf_link_extra", dir_fd, &link_extra_fd);
        if (r != 0 && r != -ENOENT)
            return bf_err_r(r, "failed to open chain's link extra");

        r = bf_link_new_from_fd(&_handle->link, &hookopts, link_fd,
                                link_extra_fd);
        if (r)
            return bf_err_r(r, "failed to restore bf_link");
    }

    r = bf_bpf_obj_get_info(_handle->prog_fd, &prog_info, sizeof(prog_info));
    if (r)
        return bf_err_r(r, "failed to get program info for '%s'", name);

    if (prog_info.nr_map_ids > 0) {
        uint32_t nr_map_ids = prog_info.nr_map_ids;

        map_ids = calloc(nr_map_ids, sizeof(*map_ids));
        if (!map_ids)
            return -ENOMEM;

        memset(&prog_info, 0, sizeof(prog_info));
        prog_info.nr_map_ids = nr_map_ids;
        prog_info.map_ids = bf_ptr_to_u64(map_ids);

        r = bf_bpf_obj_get_info(_handle->prog_fd, &prog_info,
                                sizeof(prog_info));
        if (r)
            return bf_err_r(r, "failed to get map IDs for '%s'", name);
    }

    for (uint32_t i = 0; i < prog_info.nr_map_ids; ++i) {
        _cleanup_close_ int map_fd = -1;
        _free_bf_map_ struct bf_map *map = NULL;

        map_fd = bf_bpf_map_get_fd_by_id(map_ids[i]);
        if (map_fd < 0) {
            return bf_err_r(map_fd, "failed to get fd for map ID %u",
                            map_ids[i]);
        }

        r = bf_map_new_from_fd(&map, map_fd);
        if (r)
            return bf_err_r(r, "failed to restore map from ID %u", map_ids[i]);

        switch (map->type) {
        case BF_MAP_TYPE_COUNTERS:
            _handle->cmap = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_PRINTER:
            _handle->pmap = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_LOG:
            _handle->lmap = TAKE_PTR(map);
            break;
        case BF_MAP_TYPE_SET:
            r = bf_list_push(&_handle->sets, (void **)&map);
            if (r)
                return r;
            break;
        default:
            return bf_err_r(-EINVAL, "unknown bf_map type %d", map->type);
        }
    }

    *handle = TAKE_PTR(_handle);

    return 0;
}

void bf_handle_free(struct bf_handle **handle)
{
    if (!*handle)
        return;

    closep(&(*handle)->prog_fd);

    bf_link_free(&(*handle)->link);
    bf_map_free(&(*handle)->cmap);
    bf_map_free(&(*handle)->pmap);
    bf_map_free(&(*handle)->lmap);
    bf_list_clean(&(*handle)->sets);

    free(*handle);
    *handle = NULL;
}

int bf_handle_pack(const struct bf_handle *handle, bf_wpack_t *pack)
{
    assert(handle);
    assert(pack);

    bf_wpack_kv_str(pack, "prog_name", handle->prog_name);

    if (handle->link) {
        bf_wpack_open_object(pack, "hookopts");
        bf_hookopts_pack(handle->link->hookopts, pack);
        bf_wpack_close_object(pack);
    } else {
        bf_wpack_kv_nil(pack, "hookopts");
    }

    return bf_wpack_is_valid(pack) ? 0 : -EINVAL;
}

void bf_handle_dump(const struct bf_handle *handle, prefix_t *prefix)
{
    assert(handle);
    assert(prefix);

    DUMP(prefix, "struct bf_handle at %p", handle);

    bf_dump_prefix_push(prefix);

    DUMP(prefix, "prog_name: %s", handle->prog_name);
    DUMP(prefix, "prog_fd: %d", handle->prog_fd);

    if (handle->link) {
        DUMP(bf_dump_prefix_last(prefix), "link: struct bf_link *");
        bf_dump_prefix_push(prefix);
        bf_link_dump(handle->link, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(bf_dump_prefix_last(prefix), "link: struct bf_link * (NULL)");
    }

    if (handle->cmap) {
        DUMP(prefix, "cmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->cmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "cmap: struct bf_map * (NULL)");
    }

    if (handle->pmap) {
        DUMP(prefix, "pmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->pmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "pmap: struct bf_map * (NULL)");
    }

    if (handle->lmap) {
        DUMP(prefix, "lmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->lmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "lmap: struct bf_map * (NULL)");
    }

    if (handle->lmap) {
        DUMP(prefix, "lmap: struct bf_map *");
        bf_dump_prefix_push(prefix);
        bf_map_dump(handle->lmap, bf_dump_prefix_last(prefix));
        bf_dump_prefix_pop(prefix);
    } else {
        DUMP(prefix, "lmap: struct bf_map * (NULL)");
    }

    DUMP(prefix, "sets: bf_list<bf_map>[%lu]", bf_list_size(&handle->sets));
    bf_dump_prefix_push(prefix);
    bf_list_foreach (&handle->sets, map_node) {
        struct bf_map *map = bf_list_node_get_data(map_node);

        if (bf_list_is_tail(&handle->sets, map_node))
            bf_dump_prefix_last(prefix);

        bf_map_dump(map, prefix);
    }
    bf_dump_prefix_pop(prefix);

    bf_dump_prefix_pop(prefix);
}

int bf_handle_pin(struct bf_handle *handle, int dir_fd)
{
    int r;

    assert(handle);

    r = bf_bpf_obj_pin(handle->prog_name, handle->prog_fd, dir_fd);
    if (r) {
        bf_err_r(r, "failed to pin BPF program");
        goto err_unpin_all;
    }

    if (handle->link) {
        r = bf_link_pin(handle->link, dir_fd);
        if (r) {
            bf_err_r(r, "failed to pin BPF link");
            goto err_unpin_all;
        }
    }

    return 0;

err_unpin_all:
    bf_handle_unpin(handle, dir_fd);
    return r;
}

void bf_handle_unpin(struct bf_handle *handle, int dir_fd)
{
    assert(handle);

    if (handle->link)
        bf_link_unpin(handle->link, dir_fd);

    unlinkat(dir_fd, handle->prog_name, 0);
}

int bf_handle_get_counter(const struct bf_handle *handle, uint32_t counter_idx,
                          struct bf_counter *counter)
{
    int r;

    assert(handle);
    assert(counter);

    if (!handle->cmap)
        return bf_err_r(-ENOENT, "handle has no counters map");

    r = bf_bpf_map_lookup_elem(handle->cmap->fd, &counter_idx, counter);
    if (r < 0)
        return bf_err_r(errno, "failed to lookup counters map");

    return 0;
}

int bf_handle_attach(struct bf_handle *handle, enum bf_hook hook,
                     struct bf_hookopts **hookopts)
{
    int r;

    assert(handle);
    assert(hookopts);

    r = bf_link_new(&handle->link, hook, hookopts, handle->prog_fd);
    if (r)
        return bf_err_r(r, "failed to attach bf_link");

    return 0;
}

void bf_handle_detach(struct bf_handle *handle)
{
    assert(handle);

    bf_link_free(&handle->link);
}

void bf_handle_unload(struct bf_handle *handle)
{
    _clean_bf_list_ bf_list list = bf_list_default_from(handle->sets);

    assert(handle);

    closep(&handle->prog_fd);
    bf_link_free(&handle->link);
    bf_map_free(&handle->cmap);
    bf_map_free(&handle->pmap);
    bf_map_free(&handle->lmap);
    bf_swap(list, handle->sets);
}
